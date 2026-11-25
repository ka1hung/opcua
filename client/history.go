package client

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// HistoryValue is one value read from history.
type HistoryValue struct {
	Value      any
	Status     ua.StatusCode
	SourceTime time.Time
	ServerTime time.Time
}

// Good reports whether the value is usable.
func (v HistoryValue) Good() bool { return uint32(v.Status)&0xC0000000 == 0 }

// Aggregate is a function the server computes over each interval of
// history (OPC 10000-13).
type Aggregate uint32

// The aggregates; servers need not support all of them.
const (
	Average Aggregate = id.AggregateFunction_Average
	Minimum Aggregate = id.AggregateFunction_Minimum
	Maximum Aggregate = id.AggregateFunction_Maximum
	Count   Aggregate = id.AggregateFunction_Count
	Start   Aggregate = id.AggregateFunction_Start
	End     Aggregate = id.AggregateFunction_End
	Total   Aggregate = id.AggregateFunction_Total
)

var aggregateNames = map[string]Aggregate{
	"average": Average, "minimum": Minimum, "maximum": Maximum,
	"count": Count, "start": Start, "end": End, "total": Total,
}

// ParseAggregate parses an aggregate name: average, minimum, maximum,
// count, start, end or total.
func ParseAggregate(name string) (Aggregate, error) {
	if a, ok := aggregateNames[strings.ToLower(strings.TrimSpace(name))]; ok {
		return a, nil
	}
	return 0, fmt.Errorf("client: unknown aggregate %q", name)
}

// historyPage is how many values one HistoryRead request asks for; the
// client follows continuation points for the rest.
const historyPage = 1000

// HistoryRaw reads the values a node had between start and end, oldest
// first (newest first when start is after end). max limits the number of
// values; 0 reads all.
func (c *Client) HistoryRaw(ctx context.Context, nodeID string, start, end time.Time, max int) ([]HistoryValue, error) {
	page := historyPage
	if max > 0 && max < page {
		page = max
	}
	details := &ua.ReadRawModifiedDetails{StartTime: start, EndTime: end, NumValuesPerNode: uint32(page)}
	return c.historyValues(ctx, nodeID, details, max)
}

// HistoryAtTime reads the value a node had at each of the times; where
// no value exists the result has a Bad status.
func (c *Client) HistoryAtTime(ctx context.Context, nodeID string, times []time.Time) ([]HistoryValue, error) {
	return c.historyValues(ctx, nodeID, &ua.ReadAtTimeDetails{ReqTimes: times, UseSimpleBounds: true}, 0)
}

// HistoryProcessed reads one value per interval between start and end,
// computed by the server with the aggregate. interval 0 makes one value
// for the whole range.
func (c *Client) HistoryProcessed(ctx context.Context, nodeID string, agg Aggregate, start, end time.Time, interval time.Duration) ([]HistoryValue, error) {
	details := &ua.ReadProcessedDetails{
		StartTime: start, EndTime: end, ProcessingInterval: float64(interval) / float64(time.Millisecond),
		AggregateType:          []*ua.NodeID{ua.NewNumericNodeID(0, uint32(agg))},
		AggregateConfiguration: &ua.AggregateConfiguration{UseServerCapabilitiesDefaults: true},
	}
	return c.historyValues(ctx, nodeID, details, 0)
}

func (c *Client) historyValues(ctx context.Context, nodeID string, details any, max int) ([]HistoryValue, error) {
	var out []HistoryValue
	err := c.historyRead(ctx, nodeID, details, func(res *ua.HistoryReadResult) bool {
		hd, ok := res.HistoryData.Value.(*ua.HistoryData)
		if !ok || hd == nil {
			return true
		}
		for _, dv := range hd.DataValues {
			hv := HistoryValue{Status: dv.Status, SourceTime: dv.SourceTimestamp, ServerTime: dv.ServerTimestamp}
			if dv.Value != nil {
				hv.Value = dv.Value.Value()
			}
			out = append(out, hv)
			if max > 0 && len(out) >= max {
				return false
			}
		}
		return true
	})
	return out, err
}

// HistoryEvents reads the events and alarms a notifier recorded between
// start and end. max limits the number of events; 0 reads all.
func (c *Client) HistoryEvents(ctx context.Context, notifier string, start, end time.Time, max int) ([]Event, error) {
	if notifier == "" {
		notifier = ServerObject
	}
	page := historyPage
	if max > 0 && max < page {
		page = max
	}
	details := &ua.ReadEventDetails{NumValuesPerNode: uint32(page), StartTime: start, EndTime: end, Filter: eventFilter()}
	var out []Event
	err := c.historyRead(ctx, notifier, details, func(res *ua.HistoryReadResult) bool {
		he, ok := res.HistoryData.Value.(*ua.HistoryEvent)
		if !ok || he == nil {
			return true
		}
		for _, ev := range he.Events {
			if ev != nil {
				out = append(out, parseEvent(ev.EventFields))
			}
			if max > 0 && len(out) >= max {
				return false
			}
		}
		return true
	})
	return out, err
}

// historyRead sends HistoryRead requests for one node, following
// continuation points while more returns true, and releases a
// continuation point it does not follow.
func (c *Client) historyRead(ctx context.Context, nodeID string, details any, more func(*ua.HistoryReadResult) bool) error {
	nid, err := c.parse(nodeID)
	if err != nil {
		return err
	}
	var cp []byte
	for {
		res, err := c.historyOnce(ctx, nid, details, cp, false)
		if err != nil {
			return fmt.Errorf("client: history of %s: %w", nodeID, err)
		}
		if st := res.StatusCode; uint32(st)&0x80000000 != 0 {
			return fmt.Errorf("client: history of %s: %w", nodeID, st)
		}
		cp = res.ContinuationPoint
		if !more(res) {
			if len(cp) > 0 {
				_, _ = c.historyOnce(ctx, nid, details, cp, true)
			}
			return nil
		}
		if len(cp) == 0 {
			return nil
		}
	}
}

func (c *Client) historyOnce(ctx context.Context, nid *ua.NodeID, details any, cp []byte, release bool) (*ua.HistoryReadResult, error) {
	hctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var res *ua.HistoryReadResult
	err := c.c.Send(hctx, &ua.HistoryReadRequest{
		HistoryReadDetails:        ua.NewExtensionObject(details),
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: release,
		NodesToRead:               []*ua.HistoryReadValueID{{NodeID: nid, ContinuationPoint: cp}},
	}, func(r ua.Response) error {
		resp, ok := r.(*ua.HistoryReadResponse)
		if !ok || len(resp.Results) != 1 {
			return fmt.Errorf("unexpected response %T", r)
		}
		res = resp.Results[0]
		return nil
	})
	return res, err
}
