package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

func call(t *testing.T, c *opcua.Client, obj, method *ua.NodeID, args ...any) *ua.CallMethodResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in := make([]*ua.Variant, len(args))
	for i, a := range args {
		in[i] = ua.MustVariant(a)
	}
	res, err := c.Call(ctx, &ua.CallMethodRequest{ObjectID: obj, MethodID: method, InputArguments: in})
	require.NoError(t, err)
	return res
}

func TestCallMethod(t *testing.T) {
	f := newFixture(t)
	obj, err := f.srv.AddObject(server.ObjectsFolder, server.ObjectSpec{NodeID: f.id("Pump"), BrowseName: "Pump"})
	require.NoError(t, err)
	var got []any
	_, err = f.srv.AddMethod(obj.ID(), server.MethodSpec{
		NodeID: f.id("Pump.Start"), BrowseName: "Start",
		InputArguments: []*ua.Argument{
			{Name: "Speed", DataType: ua.NewNumericNodeID(0, id.Double), ValueRank: -1},
			{Name: "Mode", DataType: ua.NewNumericNodeID(0, id.Int32), ValueRank: -1},
		},
		OutputArguments: []*ua.Argument{{Name: "Ok", DataType: ua.NewNumericNodeID(0, id.Boolean), ValueRank: -1}},
		Handler: func(ctx context.Context, who *server.Identity, o *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
			got = []any{who.UserName, o.String(), args[0].Value(), args[1].Value()}
			return []*ua.Variant{ua.MustVariant(true)}, ua.StatusOK
		},
	})
	require.NoError(t, err)

	admin, err := f.client(t, ua.SecurityPolicyURINone, "admin", "secret")
	require.NoError(t, err)
	res := call(t, admin, f.id("Pump"), f.id("Pump.Start"), 1500.0, int32(2))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.Equal(t, true, res.OutputArguments[0].Value())
	require.Equal(t, []any{"admin", "ns=2;s=Pump", 1500.0, int32(2)}, got)

	// Integers are accepted for a Double argument, as for writes.
	require.Equal(t, ua.StatusOK, call(t, admin, f.id("Pump"), f.id("Pump.Start"), int32(10), int32(2)).StatusCode)

	res = call(t, admin, f.id("Pump"), f.id("Pump.Start"), "fast", int32(2))
	require.Equal(t, ua.StatusBadInvalidArgument, res.StatusCode)
	require.Equal(t, []ua.StatusCode{ua.StatusBadTypeMismatch, ua.StatusOK}, res.InputArgumentResults)
	require.Equal(t, ua.StatusBadArgumentsMissing, call(t, admin, f.id("Pump"), f.id("Pump.Start"), 1.0).StatusCode)
	require.Equal(t, ua.StatusBadTooManyArguments, call(t, admin, f.id("Pump"), f.id("Pump.Start"), 1.0, int32(1), true).StatusCode)
	require.Equal(t, ua.StatusBadMethodInvalid, call(t, admin, f.id("Points"), f.id("Pump.Start"), 1.0, int32(1)).StatusCode,
		"the method is not a component of Points")
	require.Equal(t, ua.StatusBadNodeIDUnknown, call(t, admin, f.id("Nope"), f.id("Pump.Start")).StatusCode)

	anon := f.anon(t)
	require.Equal(t, ua.StatusBadUserAccessDenied, call(t, anon, f.id("Pump"), f.id("Pump.Start"), 1.0, int32(1)).StatusCode)
}

func eventFilter(where *ua.ContentFilter, fields ...string) *ua.EventFilter {
	ef := &ua.EventFilter{WhereClause: where}
	for _, name := range fields {
		ef.SelectClauses = append(ef.SelectClauses, &ua.SimpleAttributeOperand{
			TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
			BrowsePath:       []*ua.QualifiedName{{Name: name}},
			AttributeID:      ua.AttributeIDValue,
		})
	}
	if ef.WhereClause == nil {
		ef.WhereClause = &ua.ContentFilter{}
	}
	return ef
}

func subscribeEvents(t *testing.T, c *opcua.Client, notifier *ua.NodeID, ef *ua.EventFilter) (chan *opcua.PublishNotificationData, *ua.MonitoredItemCreateResult) {
	t.Helper()
	ctx := context.Background()
	ch := make(chan *opcua.PublishNotificationData, 32)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, ch)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sub.Cancel(context.Background()) })
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:  &ua.ReadValueID{NodeID: notifier, AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode: ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{
			ClientHandle: 7, QueueSize: 100, DiscardOldest: true, SamplingInterval: 0,
			Filter: ua.NewExtensionObject(ef),
		},
	})
	require.NoError(t, err)
	return ch, res.Results[0]
}

func nextEvent(t *testing.T, ch chan *opcua.PublishNotificationData, within time.Duration) []*ua.Variant {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case n := <-ch:
			require.NoError(t, n.Error)
			if el, ok := n.Value.(*ua.EventNotificationList); ok && len(el.Events) > 0 {
				return el.Events[0].EventFields
			}
		case <-deadline:
			return nil
		}
	}
}

func literal(v any) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(v)})
}

func field(name string) *ua.ExtensionObject {
	return ua.NewExtensionObject(&ua.SimpleAttributeOperand{
		TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
		BrowsePath:       []*ua.QualifiedName{{Name: name}},
		AttributeID:      ua.AttributeIDValue,
	})
}

func TestEventsWithWhereClause(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)

	where := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		{FilterOperator: ua.FilterOperatorAnd, FilterOperands: []*ua.ExtensionObject{
			ua.NewExtensionObject(&ua.ElementOperand{Index: 1}),
			ua.NewExtensionObject(&ua.ElementOperand{Index: 2}),
		}},
		{FilterOperator: ua.FilterOperatorGreaterThan, FilterOperands: []*ua.ExtensionObject{field("Severity"), literal(uint16(500))}},
		{FilterOperator: ua.FilterOperatorLike, FilterOperands: []*ua.ExtensionObject{field("SourceName"), literal("T%")}},
	}}
	ch, res := subscribeEvents(t, c, ua.NewNumericNodeID(0, id.Server), eventFilter(where, "Message", "Severity", "SourceName", "EventType"))
	require.Equal(t, ua.StatusOK, res.StatusCode)

	require.NoError(t, f.srv.FireEvent(&server.Event{Source: f.id("Temp"), Message: "low", Severity: 100}))
	require.NoError(t, f.srv.FireEvent(&server.Event{Source: f.id("Count"), Message: "other source", Severity: 900}))
	require.NoError(t, f.srv.FireEvent(&server.Event{Source: f.id("Temp"), Message: "high", Severity: 800}))

	ev := nextEvent(t, ch, 2*time.Second)
	require.NotNil(t, ev)
	require.Equal(t, "high", ev[0].Value().(*ua.LocalizedText).Text)
	require.Equal(t, uint16(800), ev[1].Value())
	require.Equal(t, "Temp", ev[2].Value())
	require.Equal(t, "i=2041", ev[3].Value().(*ua.NodeID).String())
	require.Nil(t, nextEvent(t, ch, 300*time.Millisecond), "the other two were filtered out")
}

// A filter with a loop, an unsupported operator or a wrong operand count is
// refused when the item is created, not evaluated (§10.2 S8).
func TestInvalidEventFiltersAreRefused(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)
	server0 := ua.NewNumericNodeID(0, id.Server)

	for name, where := range map[string]*ua.ContentFilter{
		"self reference": {Elements: []*ua.ContentFilterElement{
			{FilterOperator: ua.FilterOperatorNot, FilterOperands: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.ElementOperand{Index: 0})}},
		}},
		"missing operand": {Elements: []*ua.ContentFilterElement{
			{FilterOperator: ua.FilterOperatorEquals, FilterOperands: []*ua.ExtensionObject{literal(int32(1))}},
		}},
		"unsupported operator": {Elements: []*ua.ContentFilterElement{
			{FilterOperator: ua.FilterOperatorRelatedTo, FilterOperands: []*ua.ExtensionObject{literal(int32(1)), literal(int32(2))}},
		}},
	} {
		_, res := subscribeEvents(t, c, server0, eventFilter(where, "Message"))
		require.Equal(t, ua.StatusBadEventFilterInvalid, res.StatusCode, name)
		require.NotNil(t, res.FilterResult, name)
	}
	_, res := subscribeEvents(t, c, server0, eventFilter(nil))
	require.Equal(t, ua.StatusBadEventFilterInvalid, res.StatusCode, "no select clause")

	_, res = subscribeEvents(t, c, f.id("Temp"), eventFilter(nil, "Message"))
	require.Equal(t, ua.StatusBadAttributeIDInvalid, res.StatusCode, "a variable is no notifier")
}

func TestEventNotifierObject(t *testing.T) {
	f := newFixture(t)
	c := f.anon(t)
	_, err := f.srv.AddObject(server.ObjectsFolder, server.ObjectSpec{NodeID: f.id("Area1"), BrowseName: "Area1", EventNotifier: true})
	require.NoError(t, err)
	_, err = f.srv.AddObject(server.ObjectsFolder, server.ObjectSpec{NodeID: f.id("Area2"), BrowseName: "Area2", EventNotifier: true})
	require.NoError(t, err)

	ch, res := subscribeEvents(t, c, f.id("Area1"), eventFilter(nil, "Message"))
	require.Equal(t, ua.StatusOK, res.StatusCode)
	require.NoError(t, f.srv.FireEvent(&server.Event{Source: f.id("Area2"), Message: "elsewhere"}))
	require.NoError(t, f.srv.FireEvent(&server.Event{Source: f.id("Area1"), Message: "here"}))
	ev := nextEvent(t, ch, 2*time.Second)
	require.NotNil(t, ev)
	require.Equal(t, "here", ev[0].Value().(*ua.LocalizedText).Text)
	require.Nil(t, nextEvent(t, ch, 300*time.Millisecond))
}
