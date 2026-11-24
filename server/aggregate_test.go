package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

const (
	infoDataValue = 0x400
	histCalc      = 0x1
	histPartial   = 0x4
	histMultiVal  = 0x10
)

func agg(n uint32) *ua.NodeID { return ua.NewNumericNodeID(0, n) }

// processed reads one aggregate per node and returns each node's values.
func processed(t *testing.T, c *opcua.Client, d *ua.ReadProcessedDetails, nodes ...*ua.NodeID) ([][]*ua.DataValue, *ua.HistoryReadResponse) {
	t.Helper()
	ids := make([]*ua.HistoryReadValueID, len(nodes))
	for i, n := range nodes {
		ids[i] = &ua.HistoryReadValueID{NodeID: n}
	}
	resp := historyRead(t, c, d, false, ids...)
	out := make([][]*ua.DataValue, len(resp.Results))
	for i, r := range resp.Results {
		if r.HistoryData != nil {
			if hd, ok := r.HistoryData.Value.(*ua.HistoryData); ok {
				out[i] = hd.DataValues
			}
		}
	}
	return out, resp
}

func TestProcessedAverageIntervals(t *testing.T) {
	f, t0 := historyFixture(t)
	c := f.anon(t)
	// Values 0..24 at minutes 0..24; 10 minute intervals over 25 minutes.
	vals, resp := processed(t, c, &ua.ReadProcessedDetails{
		StartTime: t0, EndTime: t0.Add(25 * time.Minute), ProcessingInterval: 600000,
		AggregateType: []*ua.NodeID{agg(id.AggregateFunction_Average)},
	}, f.id("Hist"))
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	require.Len(t, vals[0], 3)
	for i, want := range []float64{4.5, 14.5, 22} {
		dv := vals[0][i]
		require.Equal(t, want, dv.Value.Value(), "interval %d", i)
		require.Equal(t, t0.Add(time.Duration(i)*10*time.Minute), dv.SourceTimestamp)
		require.Equal(t, ua.StatusCode(0), dv.Status&0xFFFF0000)
		require.Equal(t, ua.StatusCode(infoDataValue|histCalc), dv.Status&^histPartial&0xFFFF)
	}
	require.Zero(t, vals[0][0].Status&histPartial)
	require.NotZero(t, vals[0][2].Status&histPartial, "the last interval is 5 minutes, not 10")

	// Backward: 30 minutes down to 0. Interval (20,30] has 21..24, the
	// value at 0 is at EndTime and not in any interval.
	vals, _ = processed(t, c, &ua.ReadProcessedDetails{
		StartTime: t0.Add(30 * time.Minute), EndTime: t0, ProcessingInterval: 600000,
		AggregateType: []*ua.NodeID{agg(id.AggregateFunction_Average)},
	}, f.id("Hist"))
	require.Len(t, vals[0], 3)
	require.Equal(t, 22.5, vals[0][0].Value.Value())
	require.Equal(t, t0.Add(30*time.Minute), vals[0][0].SourceTimestamp)
	require.Equal(t, 15.5, vals[0][1].Value.Value())
	require.Equal(t, 5.5, vals[0][2].Value.Value())

	// ProcessingInterval 0 is one interval over the whole range.
	vals, _ = processed(t, c, &ua.ReadProcessedDetails{
		StartTime: t0, EndTime: t0.Add(time.Hour),
		AggregateType: []*ua.NodeID{agg(id.AggregateFunction_Average)},
	}, f.id("Hist"))
	require.Len(t, vals[0], 1)
	require.Equal(t, 12.0, vals[0][0].Value.Value())

	// An interval with no values.
	vals, _ = processed(t, c, &ua.ReadProcessedDetails{
		StartTime: t0.Add(time.Hour), EndTime: t0.Add(2 * time.Hour), ProcessingInterval: 3600000,
		AggregateType: []*ua.NodeID{agg(id.AggregateFunction_Average)},
	}, f.id("Hist"))
	require.Equal(t, ua.StatusBadNoData, vals[0][0].Status)
}

func TestProcessedOtherAggregates(t *testing.T) {
	f, t0 := historyFixture(t)
	c := f.anon(t)
	hist := f.id("Hist")
	vals, resp := processed(t, c, &ua.ReadProcessedDetails{
		StartTime: t0.Add(5 * time.Minute), EndTime: t0.Add(15 * time.Minute), ProcessingInterval: 600000,
		AggregateType: []*ua.NodeID{
			agg(id.AggregateFunction_Minimum), agg(id.AggregateFunction_Maximum), agg(id.AggregateFunction_Count),
			agg(id.AggregateFunction_Start), agg(id.AggregateFunction_End), agg(id.AggregateFunction_Total),
		},
	}, hist, hist, hist, hist, hist, hist)
	for i := 0; i < 5; i++ {
		require.Equal(t, ua.StatusOK, resp.Results[i].StatusCode, "aggregate %d", i)
		require.Len(t, vals[i], 1)
	}
	min, max, count, start, end := vals[0][0], vals[1][0], vals[2][0], vals[3][0], vals[4][0]
	require.Equal(t, 5.0, min.Value.Value())
	require.Equal(t, t0.Add(5*time.Minute), min.SourceTimestamp, "the time of the minimum")
	require.Equal(t, 14.0, max.Value.Value())
	require.Equal(t, t0.Add(14*time.Minute), max.SourceTimestamp)
	require.Equal(t, uint32(10), count.Value.Value())
	require.Equal(t, 5.0, start.Value.Value())
	require.Equal(t, 14.0, end.Value.Value())
	require.Equal(t, ua.StatusCode(infoDataValue|histCalc), min.Status)
	require.Equal(t, ua.StatusCode(infoDataValue), start.Status, "Start returns a raw value")
	require.Equal(t, ua.StatusBadAggregateNotSupported, resp.Results[5].StatusCode)
}

func TestProcessedDataQuality(t *testing.T) {
	f, t0 := historyFixture(t)
	c := f.anon(t)
	d := &ua.ReadProcessedDetails{
		StartTime: t0, EndTime: t0.Add(10 * time.Minute),
		AggregateType:          []*ua.NodeID{agg(id.AggregateFunction_Average)},
		AggregateConfiguration: &ua.AggregateConfiguration{UseServerCapabilitiesDefaults: true},
	}
	// Server defaults: uncertain counts as bad, all data must be good for
	// a good result. 7 of 10 values are good.
	vals, _ := processed(t, c, d, f.id("HistQ"))
	dv := vals[0][0]
	require.Equal(t, ua.StatusUncertainDataSubNormal, dv.Status&0xFFFF0000)
	require.InDelta(t, 31.0/7, dv.Value.Value(), 1e-9, "bad values are left out")

	// Uncertain counts as good, 70% good is enough.
	d.AggregateConfiguration = &ua.AggregateConfiguration{TreatUncertainAsBad: false, PercentDataGood: 70, PercentDataBad: 30}
	vals, _ = processed(t, c, d, f.id("HistQ"))
	dv = vals[0][0]
	require.Equal(t, ua.StatusOK, dv.Status&0xFFFF0000)
	require.Equal(t, 38.0/8, dv.Value.Value())

	// Too much bad data.
	d.AggregateConfiguration = &ua.AggregateConfiguration{TreatUncertainAsBad: true, PercentDataGood: 100, PercentDataBad: 20}
	vals, _ = processed(t, c, d, f.id("HistQ"))
	require.Equal(t, ua.StatusBad, vals[0][0].Status&0xFFFF0000)

	d.AggregateConfiguration = &ua.AggregateConfiguration{PercentDataGood: 101}
	_, resp := processed(t, c, d, f.id("HistQ"))
	require.Equal(t, ua.StatusBadAggregateConfigurationRejected, resp.Results[0].StatusCode)
}

func TestProcessedChecksAndPages(t *testing.T) {
	f, t0 := historyFixture(t)
	c := f.anon(t)
	avg := []*ua.NodeID{agg(id.AggregateFunction_Average)}

	_, resp := processed(t, c, &ua.ReadProcessedDetails{StartTime: t0, EndTime: t0.Add(time.Hour), AggregateType: avg},
		f.id("Hist"), f.id("HistQ"))
	require.Equal(t, ua.StatusBadAggregateListMismatch, resp.Results[0].StatusCode)
	_, resp = processed(t, c, &ua.ReadProcessedDetails{StartTime: t0, EndTime: t0, AggregateType: avg}, f.id("Hist"))
	require.Equal(t, ua.StatusBadInvalidArgument, resp.Results[0].StatusCode)
	_, resp = processed(t, c, &ua.ReadProcessedDetails{StartTime: t0, AggregateType: avg}, f.id("Hist"))
	require.Equal(t, ua.StatusBadInvalidTimestampArgument, resp.Results[0].StatusCode)
	_, resp = processed(t, c, &ua.ReadProcessedDetails{StartTime: t0, EndTime: t0.Add(time.Hour), AggregateType: avg}, f.id("Temp"))
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	_, resp = processed(t, c, &ua.ReadProcessedDetails{StartTime: t0, EndTime: t0.Add(time.Hour), AggregateType: avg}, f.id("Secret"))
	require.Equal(t, ua.StatusBadUserAccessDenied, resp.Results[0].StatusCode)

	// 25 minutes in 100 ms intervals is 15000 intervals: two responses.
	d := &ua.ReadProcessedDetails{StartTime: t0, EndTime: t0.Add(25 * time.Minute), ProcessingInterval: 100,
		AggregateType: []*ua.NodeID{agg(id.AggregateFunction_Count)}}
	var n int
	var total uint32
	var cp []byte
	for page := 0; page < 3; page++ {
		resp := historyRead(t, c, d, false, &ua.HistoryReadValueID{NodeID: f.id("Hist"), ContinuationPoint: cp})
		require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
		for _, dv := range resp.Results[0].HistoryData.Value.(*ua.HistoryData).DataValues {
			n++
			total += dv.Value.Value().(uint32)
		}
		cp = resp.Results[0].ContinuationPoint
		if cp == nil {
			break
		}
	}
	require.Equal(t, 15000, n)
	require.Equal(t, uint32(25), total)
}

func TestAggregateCapabilities(t *testing.T) {
	f, _ := historyFixture(t)
	c := f.anon(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var resp *ua.BrowseResponse
	require.NoError(t, c.Send(ctx, &ua.BrowseRequest{
		NodesToBrowse: []*ua.BrowseDescription{{
			NodeID: ua.NewNumericNodeID(0, id.HistoryServerCapabilities_AggregateFunctions), BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes), IncludeSubtypes: true, ResultMask: uint32(ua.BrowseResultMaskAll),
		}},
	}, func(r ua.Response) error {
		resp = r.(*ua.BrowseResponse)
		return nil
	}))
	var names []string
	for _, r := range resp.Results[0].References {
		names = append(names, r.BrowseName.Name)
	}
	require.Equal(t, []string{"Average", "Minimum", "Maximum", "Count", "Start", "End"}, names)

	v, err := c.Node(ua.NewNumericNodeID(0, id.HistoryServerCapabilities_AccessHistoryDataCapability)).Value(ctx)
	require.NoError(t, err)
	require.Equal(t, true, v.Value())
}
