package server_test

import (
	"context"
	"encoding/binary"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

// memHistory is a HistoryReader over values and events kept in memory.
type memHistory struct {
	values map[string][]*ua.DataValue // by node id, ascending
	events []*server.Event
}

func pos(cont []byte) int {
	if len(cont) == 0 {
		return 0
	}
	return int(binary.LittleEndian.Uint32(cont))
}

func cont(i int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(i))
	return b
}

func (h *memHistory) ReadRaw(ctx context.Context, node *ua.NodeID, start, end time.Time, max int, bounds bool, c []byte) ([]*ua.DataValue, []byte, error) {
	var in []*ua.DataValue
	for _, v := range h.values[node.String()] {
		if (start.IsZero() || !v.SourceTimestamp.Before(start)) && (end.IsZero() || !v.SourceTimestamp.After(end)) {
			in = append(in, v)
		}
	}
	from := pos(c)
	to := from + max
	if to >= len(in) {
		return in[from:], nil, nil
	}
	return in[from:to], cont(to), nil
}

func (h *memHistory) ReadAtTime(ctx context.Context, node *ua.NodeID, times []time.Time) ([]*ua.DataValue, error) {
	vals := h.values[node.String()]
	out := make([]*ua.DataValue, len(times))
	for i, t := range times {
		j := sort.Search(len(vals), func(k int) bool { return vals[k].SourceTimestamp.After(t) })
		if j == 0 {
			out[i] = &ua.DataValue{Status: ua.StatusBadNoData, SourceTimestamp: t}
		} else {
			out[i] = vals[j-1]
		}
	}
	return out, nil
}

func (h *memHistory) ReadEvents(ctx context.Context, notifier *ua.NodeID, start, end time.Time, max int, c []byte) ([]*server.Event, []byte, error) {
	var in []*server.Event
	for _, e := range h.events {
		if !e.Time.Before(start) && (end.IsZero() || !e.Time.After(end)) {
			in = append(in, e)
		}
	}
	from := pos(c)
	to := from + max
	if to >= len(in) {
		return in[from:], nil, nil
	}
	return in[from:to], cont(to), nil
}

func historyFixture(t *testing.T) (*fixture, time.Time) {
	f := newFixture(t)
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	h := &memHistory{values: map[string][]*ua.DataValue{}}
	for i := 0; i < 25; i++ {
		ts := t0.Add(time.Duration(i) * time.Minute)
		h.values["ns=2;s=Hist"] = append(h.values["ns=2;s=Hist"], &ua.DataValue{
			Value: ua.MustVariant(float64(i)), SourceTimestamp: ts,
		})
	}
	// HistQ: 0..9 at minutes 0..9; 2 and 5 are bad, 7 is uncertain.
	for i := 0; i < 10; i++ {
		dv := &ua.DataValue{Value: ua.MustVariant(float64(i)), SourceTimestamp: t0.Add(time.Duration(i) * time.Minute)}
		switch i {
		case 2, 5:
			dv.Status = ua.StatusBadSensorFailure
		case 7:
			dv.Status = ua.StatusUncertain
		}
		h.values["ns=2;s=HistQ"] = append(h.values["ns=2;s=HistQ"], dv)
	}
	h.events = []*server.Event{
		{Source: f.id("Temp"), Time: t0.Add(time.Minute), Message: "a", Severity: 100},
		{Source: f.id("Temp"), Time: t0.Add(2 * time.Minute), Message: "b", Severity: 900},
		{Source: f.id("Temp"), Time: t0.Add(3 * time.Minute), Message: "c", Severity: 900},
	}
	f.srv.SetHistory(h)
	_, err := f.srv.AddVariable(f.id("Points"), server.VariableSpec{
		NodeID: f.id("Hist"), BrowseName: "Hist", DataType: ua.TypeIDDouble, Historizing: true, Value: 24.0,
	})
	require.NoError(t, err)
	_, err = f.srv.AddVariable(f.id("Points"), server.VariableSpec{
		NodeID: f.id("HistQ"), BrowseName: "HistQ", DataType: ua.TypeIDDouble, Historizing: true, Value: 9.0,
	})
	require.NoError(t, err)
	_, err = f.srv.AddVariable(f.id("Points"), server.VariableSpec{
		NodeID: f.id("Secret"), BrowseName: "Secret", DataType: ua.TypeIDDouble, Historizing: true, Value: 1.0,
		CanRead: func(who *server.Identity) bool { return !who.Anonymous() },
	})
	require.NoError(t, err)
	return f, t0
}

func historyRead(t *testing.T, c *opcua.Client, details any, release bool, nodes ...*ua.HistoryReadValueID) *ua.HistoryReadResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var resp *ua.HistoryReadResponse
	require.NoError(t, c.Send(ctx, &ua.HistoryReadRequest{
		HistoryReadDetails:        ua.NewExtensionObject(details),
		TimestampsToReturn:        ua.TimestampsToReturnBoth,
		ReleaseContinuationPoints: release,
		NodesToRead:               nodes,
	}, func(r ua.Response) error {
		resp = r.(*ua.HistoryReadResponse)
		return nil
	}))
	return resp
}

func TestHistoryReadRawPages(t *testing.T) {
	f, t0 := historyFixture(t)
	c := f.anon(t)
	details := &ua.ReadRawModifiedDetails{StartTime: t0, EndTime: t0.Add(time.Hour), NumValuesPerNode: 10}

	var got []float64
	var cp []byte
	for page := 0; page < 5; page++ {
		resp := historyRead(t, c, details, false, &ua.HistoryReadValueID{NodeID: f.id("Hist"), ContinuationPoint: cp})
		res := resp.Results[0]
		require.Equal(t, ua.StatusOK, res.StatusCode)
		for _, dv := range res.HistoryData.Value.(*ua.HistoryData).DataValues {
			got = append(got, dv.Value.Value().(float64))
		}
		cp = res.ContinuationPoint
		if cp == nil {
			break
		}
	}
	require.Len(t, got, 25)
	require.Equal(t, 0.0, got[0])
	require.Equal(t, 24.0, got[24])

	// A released continuation point cannot be used.
	resp := historyRead(t, c, details, false, &ua.HistoryReadValueID{NodeID: f.id("Hist")})
	cp = resp.Results[0].ContinuationPoint
	require.NotNil(t, cp)
	historyRead(t, c, details, true, &ua.HistoryReadValueID{NodeID: f.id("Hist"), ContinuationPoint: cp})
	resp = historyRead(t, c, details, false, &ua.HistoryReadValueID{NodeID: f.id("Hist"), ContinuationPoint: cp})
	require.Equal(t, ua.StatusBadContinuationPointInvalid, resp.Results[0].StatusCode)
}

func TestHistoryReadAtTimeAndChecks(t *testing.T) {
	f, t0 := historyFixture(t)
	c := f.anon(t)
	resp := historyRead(t, c, &ua.ReadAtTimeDetails{ReqTimes: []time.Time{t0.Add(-time.Minute), t0.Add(90 * time.Second)}}, false,
		&ua.HistoryReadValueID{NodeID: f.id("Hist")})
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	vals := resp.Results[0].HistoryData.Value.(*ua.HistoryData).DataValues
	require.Equal(t, ua.StatusBadNoData, vals[0].Status)
	require.Equal(t, 1.0, vals[1].Value.Value(), "the value at 1:30 is the one stored at 1:00")

	details := &ua.ReadRawModifiedDetails{StartTime: t0, EndTime: t0.Add(time.Hour)}
	resp = historyRead(t, c, details, false,
		&ua.HistoryReadValueID{NodeID: f.id("Temp")},   // not historizing
		&ua.HistoryReadValueID{NodeID: f.id("Secret")}, // anonymous may not read it
		&ua.HistoryReadValueID{NodeID: f.id("Nope")},
	)
	require.Equal(t, ua.StatusBadHistoryOperationUnsupported, resp.Results[0].StatusCode)
	require.Equal(t, ua.StatusBadUserAccessDenied, resp.Results[1].StatusCode)
	require.Equal(t, ua.StatusBadNodeIDUnknown, resp.Results[2].StatusCode)
}

func TestHistoryReadEvents(t *testing.T) {
	f, t0 := historyFixture(t)
	c := f.anon(t)
	where := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		{FilterOperator: ua.FilterOperatorGreaterThan, FilterOperands: []*ua.ExtensionObject{field("Severity"), literal(uint16(500))}},
	}}
	resp := historyRead(t, c, &ua.ReadEventDetails{
		StartTime: t0, EndTime: t0.Add(time.Hour),
		Filter: eventFilter(where, "Message", "Severity"),
	}, false, &ua.HistoryReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server)})
	require.Equal(t, ua.StatusOK, resp.Results[0].StatusCode)
	evs := resp.Results[0].HistoryData.Value.(*ua.HistoryEvent).Events
	require.Len(t, evs, 2)
	require.Equal(t, "b", evs[0].EventFields[0].Value().(*ua.LocalizedText).Text)
	require.Equal(t, "c", evs[1].EventFields[0].Value().(*ua.LocalizedText).Text)
}
