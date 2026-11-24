package client_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua/client"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

// plant adds an object with events, a method and an alarm source to s.
func plant(t *testing.T, s *testServer) (area, temp *ua.NodeID) {
	t.Helper()
	srv := s.srv
	area = ua.NewStringNodeID(2, "Plant")
	_, err := srv.AddObject(server.ObjectsFolder, server.ObjectSpec{NodeID: area, BrowseName: "Plant", EventNotifier: true, EventHistory: true})
	require.NoError(t, err)
	temp = ua.NewStringNodeID(2, "Temp")
	_, err = srv.AddVariable(area, server.VariableSpec{NodeID: temp, BrowseName: "Temp", Description: "temperature",
		DataType: ua.TypeIDDouble, Writable: true, Unit: "°C", EURange: &server.Range{Low: 0, High: 100}, Historizing: true, Value: 20.0})
	require.NoError(t, err)
	_, err = srv.AddMethod(area, server.MethodSpec{
		NodeID: ua.NewStringNodeID(2, "Plant.Scale"), BrowseName: "Scale",
		InputArguments: []*ua.Argument{
			{Name: "Value", DataType: ua.NewNumericNodeID(0, 11), ValueRank: -1},
			{Name: "Factor", DataType: ua.NewNumericNodeID(0, 6), ValueRank: -1},
		},
		OutputArguments: []*ua.Argument{{Name: "Result", DataType: ua.NewNumericNodeID(0, 11), ValueRank: -1}},
		Handler: func(ctx context.Context, who *server.Identity, obj *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			v := args[0].Value().(float64) * float64(args[1].Value().(int32))
			return []*ua.Variant{ua.MustVariant(v)}, ua.StatusOK
		},
	})
	require.NoError(t, err)
	return area, temp
}

func TestAttributesTranslateStatus(t *testing.T) {
	s := newServer(t, false, server.AnonymousReadOnly(false))
	plant(t, s)
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	ctx := context.Background()

	got, err := c.Translate(ctx, "i=85", "2:Plant", "2:Temp")
	require.NoError(t, err)
	require.Equal(t, "ns=2;s=Temp", got)
	_, err = c.Translate(ctx, "i=85", "2:Plant", "2:Nothing")
	require.Error(t, err)

	info, err := c.Attributes(ctx, "ns=2;s=Temp")
	require.NoError(t, err)
	require.Equal(t, ua.NodeClassVariable, info.NodeClass)
	require.Equal(t, "2:Temp", info.BrowseName)
	require.Equal(t, "temperature", info.Description)
	require.Equal(t, "Double", info.DataType)
	require.Equal(t, int32(-1), info.ValueRank)
	require.True(t, info.CanRead() && info.CanWrite() && info.HasHistory())

	obj, err := c.Attributes(ctx, "ns=2;s=Plant")
	require.NoError(t, err)
	require.True(t, obj.HasEvents())
	m, err := c.Attributes(ctx, "ns=2;s=Plant.Scale")
	require.NoError(t, err)
	require.True(t, m.Executable && m.UserExecutable)
	_, err = c.Attributes(ctx, "ns=2;s=Missing")
	require.Error(t, err)

	st, err := c.ServerStatus(ctx)
	require.NoError(t, err)
	require.Equal(t, "Running", st.State)
	require.False(t, st.StartTime.IsZero())

	ns, err := c.Namespaces(ctx)
	require.NoError(t, err)
	require.Equal(t, "urn:test:points", ns[2])

	eps, err := client.Endpoints(ctx, s.ep, 0)
	require.NoError(t, err)
	require.Len(t, eps, 1)
	require.Equal(t, "None", eps[0].Policy)
	require.Contains(t, eps[0].UserTokens, "UserName")
}

func TestCall(t *testing.T) {
	s := newServer(t, false)
	area, _ := plant(t, s)
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity(), Auth: client.UserPass("op", "pw")})
	ctx := context.Background()

	in, out, err := c.MethodArguments(ctx, "ns=2;s=Plant.Scale")
	require.NoError(t, err)
	require.Len(t, in, 2)
	require.Equal(t, "Value", in[0].Name)
	require.Equal(t, "Double", in[0].DataType)
	require.Equal(t, "Int32", in[1].DataType)
	require.Len(t, out, 1)

	// Text from a form is converted to each argument's type.
	res, err := c.Call(ctx, area.String(), "ns=2;s=Plant.Scale", "2.5", "4")
	require.NoError(t, err)
	require.Equal(t, []any{10.0}, res)

	_, err = c.Call(ctx, area.String(), "ns=2;s=Plant.Scale", 1.0)
	var ce *client.CallError
	require.ErrorAs(t, err, &ce, "a missing argument is refused")
	require.Equal(t, ua.StatusBadArgumentsMissing, ce.Status)

	_, err = c.Call(ctx, area.String(), "ns=2;s=Plant.Scale", "abc", 1)
	require.Error(t, err, "text that is not a number")
}

func TestSubscribeWithDeadband(t *testing.T) {
	s := newServer(t, false)
	_, temp := plant(t, s)
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})

	var mu sync.Mutex
	var got []float64
	sub, rs, err := c.SubscribeWith(context.Background(), []string{"ns=2;s=Temp", "ns=2;s=D"},
		client.SubscribeOptions{Interval: 50 * time.Millisecond, PercentDeadband: 5},
		func(id string, r client.Result) {
			if id == "ns=2;s=Temp" {
				mu.Lock()
				got = append(got, r.Value.(float64))
				mu.Unlock()
			}
		})
	require.NoError(t, err)
	defer sub.Close()
	require.Equal(t, ua.StatusOK, rs[0].Status)
	require.NotEqual(t, ua.StatusOK, rs[1].Status, "a percent deadband needs an EURange")

	time.Sleep(200 * time.Millisecond)
	for _, v := range []float64{21, 22, 30, 31, 40} { // 5 % of 0..100 is 5
		require.NoError(t, s.srv.SetValue(temp, v, ua.StatusOK, time.Time{}))
		time.Sleep(100 * time.Millisecond)
	}
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 3 && got[len(got)-1] == 40
	}, 3*time.Second, 50*time.Millisecond)
	mu.Lock()
	require.Equal(t, []float64{20, 30, 40}, got)
	mu.Unlock()
}

func TestEventsAndAlarms(t *testing.T) {
	s := newServer(t, false)
	area, temp := plant(t, s)
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity(), Auth: client.UserPass("op", "pw")})
	ctx := context.Background()

	// An alarm raised before subscribing is learned through Refresh.
	require.NoError(t, s.srv.SetAlarm(server.Alarm{Source: temp, Name: "High", Active: true, Severity: 700, Message: "too hot"}))

	evs := make(chan client.Event, 100)
	sub, err := c.SubscribeEvents(ctx, area.String(), 50*time.Millisecond, func(e client.Event) { evs <- e })
	require.NoError(t, err)
	defer sub.Close()
	require.NoError(t, sub.Refresh(ctx))

	next := func(match func(client.Event) bool) client.Event {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case e := <-evs:
				if match(e) {
					return e
				}
			case <-deadline:
				t.Fatal("event did not arrive")
			}
		}
	}
	next(func(e client.Event) bool { return e.RefreshStart })
	alarm := next(func(e client.Event) bool { return e.IsCondition() })
	require.Equal(t, "High", alarm.ConditionName)
	require.Equal(t, "too hot", alarm.Message)
	require.Equal(t, uint16(700), alarm.Severity)
	require.Equal(t, temp.String(), alarm.Source)
	require.True(t, alarm.Active && !alarm.Acked && alarm.Retain)
	next(func(e client.Event) bool { return e.RefreshEnd })

	// Another area has no alarms: its refresh brings none.
	other := ua.NewStringNodeID(2, "Other")
	_, err = s.srv.AddObject(server.ObjectsFolder, server.ObjectSpec{NodeID: other, BrowseName: "Other", EventNotifier: true})
	require.NoError(t, err)
	otherEvs := make(chan client.Event, 10)
	osub, err := c.SubscribeEvents(ctx, other.String(), 50*time.Millisecond, func(e client.Event) { otherEvs <- e })
	require.NoError(t, err)
	defer osub.Close()
	require.NoError(t, osub.Refresh(ctx))
	for _, want := range []string{"start", "end"} {
		select {
		case e := <-otherEvs:
			require.False(t, e.IsCondition(), "refresh of another area must not send this alarm")
			require.True(t, e.RefreshStart && want == "start" || e.RefreshEnd && want == "end")
		case <-time.After(5 * time.Second):
			t.Fatal("refresh markers did not arrive")
		}
	}

	// Acknowledge from the client; the server records it.
	require.NoError(t, c.Acknowledge(ctx, alarm, "seen"))
	acked := next(func(e client.Event) bool { return e.IsCondition() && e.Acked })
	require.True(t, acked.Active)
	st := s.srv.Alarms()
	require.Len(t, st, 1)
	require.True(t, st[0].Acked)
	require.Equal(t, "seen", st[0].Comment)

	// An old event id is refused.
	err = c.Acknowledge(ctx, alarm, "again")
	var ce *client.CallError
	require.ErrorAs(t, err, &ce)

	// A plain event, and an event is not a condition.
	require.NoError(t, s.srv.FireEvent(&server.Event{Source: area, Message: "hello", Severity: 300}))
	plain := next(func(e client.Event) bool { return e.Message == "hello" })
	require.False(t, plain.IsCondition())
	require.Error(t, c.Acknowledge(ctx, plain, ""))
}

type memHistory struct {
	values []*ua.DataValue
	events []*server.Event
}

func (h *memHistory) ReadRaw(ctx context.Context, node *ua.NodeID, start, end time.Time, max int, bounds bool, cont []byte) ([]*ua.DataValue, []byte, error) {
	var in []*ua.DataValue
	for _, v := range h.values {
		if !v.SourceTimestamp.Before(start) && !v.SourceTimestamp.After(end) {
			in = append(in, v)
		}
	}
	from, _ := strconv.Atoi(string(cont))
	if max > 0 && from+max < len(in) {
		return in[from : from+max], []byte(strconv.Itoa(from + max)), nil
	}
	return in[from:], nil, nil
}

func (h *memHistory) ReadAtTime(ctx context.Context, node *ua.NodeID, times []time.Time) ([]*ua.DataValue, error) {
	out := make([]*ua.DataValue, len(times))
	for i, tm := range times {
		out[i] = &ua.DataValue{Status: ua.StatusBadNoData, SourceTimestamp: tm}
		for _, v := range h.values {
			if !v.SourceTimestamp.After(tm) {
				out[i] = v
			}
		}
	}
	return out, nil
}

func (h *memHistory) ReadEvents(ctx context.Context, notifier *ua.NodeID, start, end time.Time, max int, cont []byte) ([]*server.Event, []byte, error) {
	return h.events, nil, nil
}

func TestHistory(t *testing.T) {
	s := newServer(t, false)
	area, _ := plant(t, s)
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	h := &memHistory{}
	for i := 0; i < 2500; i++ { // more than one page
		h.values = append(h.values, &ua.DataValue{Value: ua.MustVariant(float64(i % 10)), SourceTimestamp: t0.Add(time.Duration(i) * time.Second),
			EncodingMask: ua.DataValueValue | ua.DataValueSourceTimestamp})
	}
	h.events = []*server.Event{{Source: area, Time: t0.Add(time.Minute), Message: "past", Severity: 400}}
	s.srv.SetHistory(h)
	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	ctx := context.Background()
	end := t0.Add(2499 * time.Second)

	raw, err := c.HistoryRaw(ctx, "ns=2;s=Temp", t0, end, 0)
	require.NoError(t, err)
	require.Len(t, raw, 2500, "follows continuation points")
	require.Equal(t, 3.0, raw[3].Value)

	some, err := c.HistoryRaw(ctx, "ns=2;s=Temp", t0, end, 5)
	require.NoError(t, err)
	require.Len(t, some, 5)

	at, err := c.HistoryAtTime(ctx, "ns=2;s=Temp", []time.Time{t0.Add(12 * time.Second), t0.Add(-time.Hour)})
	require.NoError(t, err)
	require.Len(t, at, 2)
	require.Equal(t, 2.0, at[0].Value)
	require.False(t, at[1].Good())

	cnt, err := c.HistoryProcessed(ctx, "ns=2;s=Temp", client.Count, t0, t0.Add(100*time.Second), 50*time.Second)
	require.NoError(t, err)
	require.Len(t, cnt, 2)
	require.EqualValues(t, 50, cnt[0].Value)
	avg, err := c.HistoryProcessed(ctx, "ns=2;s=Temp", client.Average, t0, t0.Add(10*time.Second), 0)
	require.NoError(t, err)
	require.Len(t, avg, 1)
	require.InDelta(t, 4.5, avg[0].Value, 1e-9)

	_, err = client.ParseAggregate("median")
	require.Error(t, err)
	a, err := client.ParseAggregate("Maximum")
	require.NoError(t, err)
	require.Equal(t, client.Maximum, a)

	evs, err := c.HistoryEvents(ctx, area.String(), t0, end, 0)
	require.NoError(t, err)
	require.Len(t, evs, 1)
	require.Equal(t, "past", evs[0].Message)
	require.Equal(t, uint16(400), evs[0].Severity)
}

var _ = errors.New

func TestAddReferenceShowsNodeTwice(t *testing.T) {
	s := newServer(t, false)
	_, temp := plant(t, s)
	legacy := ua.NewStringNodeID(2, "Data")
	_, err := s.srv.AddFolder(server.ObjectsFolder, legacy, "Data")
	require.NoError(t, err)
	organizes := ua.NewNumericNodeID(0, 35)
	require.NoError(t, s.srv.AddReference(legacy, organizes, temp))
	require.Error(t, s.srv.AddReference(legacy, organizes, ua.NewStringNodeID(2, "Missing")))
	require.Error(t, s.srv.AddReference(legacy, temp, temp), "the reference type must be a ReferenceType")

	c := dial(t, s.ep, client.Options{Security: client.NoSecurity()})
	items, err := c.Browse(context.Background(), legacy.String())
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "ns=2;s=Temp", items[0].NodeID)
	items, err = c.Browse(context.Background(), "ns=2;s=Plant")
	require.NoError(t, err)
	found := false
	for _, it := range items {
		found = found || it.NodeID == "ns=2;s=Temp"
	}
	require.True(t, found, "still below its own parent")
}

// A server that advertises a host name the client cannot resolve is still
// reached at the host the client dialled.
func TestAdvertisedHostNameIsNotResolved(t *testing.T) {
	cert, key := testCert(t, "urn:test:server")
	port := freePort(t)
	srv := server.New(server.Certificate(cert), server.PrivateKey(key),
		server.EndPoint("no-such-host.invalid", port), server.ListenAddress(fmt.Sprintf("127.0.0.1:%d", port)),
		server.EnableSecurity("None", ua.MessageSecurityModeNone), server.EnableAuthMode(ua.UserTokenTypeAnonymous))
	require.NoError(t, srv.Start(context.Background()))
	defer srv.Close()

	eps, err := client.Endpoints(context.Background(), fmt.Sprintf("opc.tcp://127.0.0.1:%d", port), 0)
	require.NoError(t, err)
	require.Contains(t, eps[0].URL, "no-such-host.invalid")
	c := dial(t, fmt.Sprintf("opc.tcp://127.0.0.1:%d", port), client.Options{Security: client.NoSecurity()})
	st, err := c.ServerStatus(context.Background())
	require.NoError(t, err)
	require.Equal(t, "Running", st.State)
}
