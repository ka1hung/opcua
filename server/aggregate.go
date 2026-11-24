package server

import (
	"context"
	"encoding/binary"
	"math"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// Processed history reads (OPC 10000-13): the server splits the time range
// into intervals and computes one value per interval from the raw values
// the HistoryReader returns.
//
// Supported aggregates: Average, Minimum, Maximum, Count, Start, End.
// Others return Bad_AggregateNotSupported.

type aggregate int

const (
	aggAverage aggregate = iota
	aggMinimum
	aggMaximum
	aggCount
	aggStart
	aggEnd
)

// aggregateIDs lists the supported aggregates in a fixed order, the order
// they are browsed in.
var aggregateIDs = []uint32{
	id.AggregateFunction_Average,
	id.AggregateFunction_Minimum,
	id.AggregateFunction_Maximum,
	id.AggregateFunction_Count,
	id.AggregateFunction_Start,
	id.AggregateFunction_End,
}

var aggregates = map[uint32]aggregate{
	id.AggregateFunction_Average: aggAverage,
	id.AggregateFunction_Minimum: aggMinimum,
	id.AggregateFunction_Maximum: aggMaximum,
	id.AggregateFunction_Count:   aggCount,
	id.AggregateFunction_Start:   aggStart,
	id.AggregateFunction_End:     aggEnd,
}

// Historian bits of a StatusCode (OPC 10000-4 §7.39): they are valid only
// with the InfoType DataValue bit set.
const (
	infoTypeDataValue  ua.StatusCode = 0x400
	historianCalc      ua.StatusCode = 0x1
	historianPartial   ua.StatusCode = 0x4
	historianMultiVal  ua.StatusCode = 0x10
	maxProcessedRawRun               = 1 << 20 // raw values asked from the reader per call to it
)

// aggConfig is an AggregateConfiguration after the server's defaults are
// applied (OPC 10000-13 §4.2.1.2).
type aggConfig struct {
	uncertainAsBad bool
	percentBad     float64
	percentGood    float64
}

func aggregateConfig(c *ua.AggregateConfiguration) (aggConfig, ua.StatusCode) {
	def := aggConfig{uncertainAsBad: true, percentBad: 100, percentGood: 100}
	if c == nil || c.UseServerCapabilitiesDefaults {
		return def, ua.StatusOK
	}
	if c.PercentDataBad > 100 || c.PercentDataGood > 100 {
		return def, ua.StatusBadAggregateConfigurationRejected
	}
	return aggConfig{uncertainAsBad: c.TreatUncertainAsBad, percentBad: float64(c.PercentDataBad), percentGood: float64(c.PercentDataGood)}, ua.StatusOK
}

// aggInterval gathers the raw values of one interval.
type aggInterval struct {
	good, bad   int
	sum         float64
	numeric     bool // all good values were numbers
	min, max    *ua.DataValue
	minF, maxF  float64
	minN, maxN  int // how often the minimum and maximum occur
	first, last *ua.DataValue
}

func (a *aggInterval) add(dv *ua.DataValue, cfg aggConfig) {
	sev := dv.Status >> 30 // 0 good, 1 uncertain, 2 or 3 bad
	if sev >= 2 || sev == 1 && cfg.uncertainAsBad || dv.Value == nil {
		a.bad++
		return
	}
	if a.good == 0 {
		a.numeric = true
		a.first = dv
	}
	a.good++
	a.last = dv
	f, ok := toFloat(dv.Value.Value())
	if !ok || math.IsNaN(f) {
		a.numeric = false
		return
	}
	a.sum += f
	switch {
	case a.min == nil || f < a.minF:
		a.min, a.minF, a.minN = dv, f, 1
	case f == a.minF:
		a.minN++
	}
	switch {
	case a.max == nil || f > a.maxF:
		a.max, a.maxF, a.maxN = dv, f, 1
	case f == a.maxF:
		a.maxN++
	}
}

// result is the aggregate's value for an interval that starts at ts.
func (a *aggInterval) result(agg aggregate, ts time.Time, partial bool, cfg aggConfig) *ua.DataValue {
	total := a.good + a.bad
	if total == 0 {
		if agg == aggCount {
			return &ua.DataValue{Value: ua.MustVariant(uint32(0)), SourceTimestamp: ts, Status: historianStatus(ua.StatusOK, historianCalc, partial)}
		}
		return &ua.DataValue{Status: ua.StatusBadNoData, SourceTimestamp: ts}
	}
	if a.good == 0 {
		return &ua.DataValue{Status: ua.StatusBadNoData, SourceTimestamp: ts}
	}
	pctGood := float64(a.good) * 100 / float64(total)
	st := ua.StatusUncertainDataSubNormal
	switch {
	case pctGood >= cfg.percentGood:
		st = ua.StatusOK
	case 100-pctGood >= cfg.percentBad:
		st = ua.StatusBad
	}

	var v *ua.Variant
	bits := historianCalc
	switch agg {
	case aggCount:
		v = ua.MustVariant(uint32(a.good))
	case aggStart, aggEnd:
		dv := a.first
		if agg == aggEnd {
			dv = a.last
		}
		v, ts, bits = dv.Value, dv.SourceTimestamp, 0
	default:
		if !a.numeric {
			return &ua.DataValue{Status: ua.StatusBadAggregateInvalidInputs, SourceTimestamp: ts}
		}
		switch agg {
		case aggAverage:
			v = ua.MustVariant(a.sum / float64(a.good))
		case aggMinimum:
			v, ts = a.min.Value, a.min.SourceTimestamp
			if a.minN > 1 {
				bits |= historianMultiVal
			}
		case aggMaximum:
			v, ts = a.max.Value, a.max.SourceTimestamp
			if a.maxN > 1 {
				bits |= historianMultiVal
			}
		}
	}
	return &ua.DataValue{Value: v, SourceTimestamp: ts, Status: historianStatus(st, bits, partial)}
}

func historianStatus(st, bits ua.StatusCode, partial bool) ua.StatusCode {
	if partial {
		bits |= historianPartial
	}
	return st | infoTypeDataValue | bits
}

// readProcessed computes one aggregate of a variable. pos is the index of
// the first interval to compute, kept in a continuation point when the
// intervals do not fit in one response.
func (s *Server) readProcessed(ctx context.Context, h HistoryReader, n *Node, d *ua.ReadProcessedDetails, aggID *ua.NodeID, pos []byte) ([]*ua.DataValue, []byte, ua.StatusCode) {
	var kind aggregate
	ok := false
	if aggID != nil && aggID.Namespace() == 0 && aggID.IntID() != 0 {
		kind, ok = aggregates[aggID.IntID()]
	}
	if !ok {
		return nil, nil, ua.StatusBadAggregateNotSupported
	}
	cfg, st := aggregateConfig(d.AggregateConfiguration)
	if st != ua.StatusOK {
		return nil, nil, st
	}
	if d.StartTime.IsZero() || d.EndTime.IsZero() {
		return nil, nil, ua.StatusBadInvalidTimestampArgument
	}
	if d.StartTime.Equal(d.EndTime) || d.ProcessingInterval < 0 || math.IsNaN(d.ProcessingInterval) || math.IsInf(d.ProcessingInterval, 0) {
		return nil, nil, ua.StatusBadInvalidArgument
	}

	// Intervals run from StartTime toward EndTime; EndTime is never in one.
	// Going backward (StartTime after EndTime) interval i holds the times
	// in (start-(i+1)pi, start-i*pi], going forward [start+i*pi,
	// start+(i+1)pi). Either way a value lies in interval floor(off/pi),
	// off being its distance from StartTime.
	start, end := d.StartTime, d.EndTime
	dir := time.Duration(1)
	if start.After(end) {
		dir = -1
	}
	span := (end.Sub(start)) * dir
	pi := span
	if f := d.ProcessingInterval * float64(time.Millisecond); f >= 1 && f < float64(span) {
		pi = time.Duration(f)
	}
	count := int64((span + pi - 1) / pi)

	first := int64(0)
	if len(pos) == 8 {
		first = int64(binary.LittleEndian.Uint64(pos))
	} else if len(pos) != 0 {
		return nil, nil, ua.StatusBadContinuationPointInvalid
	}
	if first >= count {
		return nil, nil, ua.StatusBadContinuationPointInvalid
	}
	last := first + maxHistoryValues
	if last > count {
		last = count
	}
	ivs := make([]aggInterval, last-first)

	// The raw values the intervals need, oldest first.
	offLo, offHi := time.Duration(first)*pi, time.Duration(last)*pi
	if offHi > span {
		offHi = span
	}
	lo, hi := start.Add(offLo*dir), start.Add(offHi*dir)
	if dir < 0 {
		lo, hi = hi, lo
	}
	var cont []byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, ua.StatusBadTimeout
		}
		vals, next, err := h.ReadRaw(ctx, n.id, lo, hi, maxProcessedRawRun, false, cont)
		if err != nil {
			return nil, nil, historyError(err)
		}
		for _, dv := range vals {
			if dv == nil {
				continue
			}
			off := dv.SourceTimestamp.Sub(start) * dir
			if off < offLo || off >= offHi {
				continue
			}
			ivs[int64(off/pi)-first].add(dv, cfg)
		}
		if next == nil {
			break
		}
		cont = next
	}

	out := make([]*ua.DataValue, len(ivs))
	for i := range ivs {
		k := first + int64(i)
		ts := start.Add(time.Duration(k) * pi * dir)
		partial := time.Duration(k+1)*pi > span
		out[i] = ivs[i].result(kind, ts, partial, cfg)
	}
	var next []byte
	if last < count {
		next = make([]byte, 8)
		binary.LittleEndian.PutUint64(next, uint64(last))
	}
	return out, next, ua.StatusOK
}
