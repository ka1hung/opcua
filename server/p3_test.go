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

// alarmFilter selects the fields the tests read, in this order.
var alarmFields = []string{"EventId", "EventType", "ConditionName", "ActiveState/Id", "AckedState/Id", "Retain", "Severity", "Message", "Comment"}

const (
	fEventID = iota
	fType
	fName
	fActive
	fAcked
	fRetain
	fSeverity
	fMessage
	fComment
	fConditionID
)

func alarmFilter() *ua.EventFilter {
	ef := &ua.EventFilter{WhereClause: &ua.ContentFilter{}}
	for _, name := range alarmFields {
		var path []*ua.QualifiedName
		for _, p := range splitPath(name) {
			path = append(path, &ua.QualifiedName{Name: p})
		}
		ef.SelectClauses = append(ef.SelectClauses, &ua.SimpleAttributeOperand{
			TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
			BrowsePath:       path,
			AttributeID:      ua.AttributeIDValue,
		})
	}
	// ConditionId: the NodeId attribute of the ConditionType, empty path.
	ef.SelectClauses = append(ef.SelectClauses, &ua.SimpleAttributeOperand{
		TypeDefinitionID: ua.NewNumericNodeID(0, id.ConditionType),
		AttributeID:      ua.AttributeIDNodeID,
	})
	return ef
}

func splitPath(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '/' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func TestAlarmLifecycle(t *testing.T) {
	f := newFixture(t)
	var ackedBy []string
	f.srv.OnAcknowledge(func(ctx context.Context, who *server.Identity, src *ua.NodeID, name, comment string) ua.StatusCode {
		ackedBy = append(ackedBy, who.UserName+":"+src.String()+":"+name+":"+comment)
		return ua.StatusOK
	})
	admin, err := f.client(t, ua.SecurityPolicyURINone, "admin", "secret")
	require.NoError(t, err)
	ch, res := subscribeEvents(t, admin, ua.NewNumericNodeID(0, id.Server), alarmFilter())
	require.Equal(t, ua.StatusOK, res.StatusCode)

	// Inactive alarms that never fired report nothing.
	require.NoError(t, f.srv.SetAlarm(server.Alarm{Source: f.id("Temp"), Name: "High", Active: false}))
	require.Nil(t, nextEvent(t, ch, 300*time.Millisecond))

	require.NoError(t, f.srv.SetAlarm(server.Alarm{Source: f.id("Temp"), Name: "High", Active: true, Severity: 700, Message: "Temp high"}))
	ev := nextEvent(t, ch, 2*time.Second)
	require.NotNil(t, ev)
	require.Equal(t, "i=2915", ev[fType].Value().(*ua.NodeID).String())
	require.Equal(t, "High", ev[fName].Value())
	require.Equal(t, true, ev[fActive].Value())
	require.Equal(t, false, ev[fAcked].Value())
	require.Equal(t, true, ev[fRetain].Value())
	require.Equal(t, uint16(700), ev[fSeverity].Value())
	cond := ev[fConditionID].Value().(*ua.NodeID)
	require.Equal(t, "ns=2;s=Temp.Condition.High", cond.String())
	eventID := ev[fEventID].Value().([]byte)

	ack := func(c *opcua.Client, evID []byte, comment string) ua.StatusCode {
		return call(t, c, cond, ua.NewNumericNodeID(0, id.AcknowledgeableConditionType_Acknowledge),
			evID, ua.NewLocalizedText(comment)).StatusCode
	}
	require.Equal(t, ua.StatusBadUserAccessDenied, ack(f.anon(t), eventID, "x"), "anonymous may not acknowledge")
	require.Equal(t, ua.StatusBadEventIDUnknown, ack(admin, []byte("old"), "x"))
	require.Equal(t, ua.StatusOK, ack(admin, eventID, "seen"))
	require.Equal(t, []string{"admin:ns=2;s=Temp:High:seen"}, ackedBy)

	ev = nextEvent(t, ch, 2*time.Second)
	require.NotNil(t, ev)
	require.Equal(t, true, ev[fActive].Value())
	require.Equal(t, true, ev[fAcked].Value())
	require.Equal(t, true, ev[fRetain].Value(), "still active")
	require.Equal(t, "seen", ev[fComment].Value().(*ua.LocalizedText).Text)
	require.Equal(t, ua.StatusBadConditionBranchAlreadyAcked, ack(admin, ev[fEventID].Value().([]byte), "again"))

	require.NoError(t, f.srv.SetAlarm(server.Alarm{Source: f.id("Temp"), Name: "High", Active: false, Severity: 700, Message: "Temp normal"}))
	ev = nextEvent(t, ch, 2*time.Second)
	require.NotNil(t, ev)
	require.Equal(t, false, ev[fActive].Value())
	require.Equal(t, false, ev[fRetain].Value(), "inactive and acknowledged")
	require.Empty(t, f.srv.Alarms())
}

// After a reconnect a client calls ConditionRefresh and gets the alarms
// that are still active or unacknowledged (OPC 10000-9 §5.5.7).
func TestConditionRefresh(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.srv.SetAlarm(server.Alarm{Source: f.id("Temp"), Name: "High", Active: true, Severity: 700}))
	require.NoError(t, f.srv.SetAlarm(server.Alarm{Source: f.id("Count"), Name: "Fault", Active: true, Severity: 900}))
	require.NoError(t, f.srv.SetAlarm(server.Alarm{Source: f.id("Count"), Name: "Fault", Active: false, Severity: 900}))
	require.Len(t, f.srv.Alarms(), 2, "Fault is inactive but not acknowledged")

	c := f.anon(t)
	ctx := context.Background()
	ch := make(chan *opcua.PublishNotificationData, 32)
	sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{Interval: 50 * time.Millisecond}, ch)
	require.NoError(t, err)
	defer sub.Cancel(ctx)
	res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, &ua.MonitoredItemCreateRequest{
		ItemToMonitor:       &ua.ReadValueID{NodeID: ua.NewNumericNodeID(0, id.Server), AttributeID: ua.AttributeIDEventNotifier},
		MonitoringMode:      ua.MonitoringModeReporting,
		RequestedParameters: &ua.MonitoringParameters{ClientHandle: 1, QueueSize: 100, Filter: ua.NewExtensionObject(alarmFilter())},
	})
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, res.Results[0].StatusCode)

	r := call(t, c, ua.NewNumericNodeID(0, id.ConditionType), ua.NewNumericNodeID(0, id.ConditionType_ConditionRefresh), sub.SubscriptionID)
	require.Equal(t, ua.StatusOK, r.StatusCode, "anonymous may refresh")

	var types []string
	names := map[string]bool{}
	deadline := time.After(3 * time.Second)
	for len(types) < 4 {
		select {
		case n := <-ch:
			if el, ok := n.Value.(*ua.EventNotificationList); ok {
				for _, e := range el.Events {
					types = append(types, e.EventFields[fType].Value().(*ua.NodeID).String())
					if name, ok := e.EventFields[fName].Value().(string); ok {
						names[name] = true
					}
				}
			}
		case <-deadline:
			t.Fatalf("got %v", types)
		}
	}
	require.Equal(t, "i=2787", types[0], "RefreshStart first")
	require.Equal(t, "i=2788", types[3], "RefreshEnd last")
	require.Equal(t, map[string]bool{"High": true, "Fault": true}, names)

	r = call(t, c, ua.NewNumericNodeID(0, id.ConditionType), ua.NewNumericNodeID(0, id.ConditionType_ConditionRefresh), uint32(9999))
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, r.StatusCode)
}

func TestAcknowledgeRefusedByApplication(t *testing.T) {
	f := newFixture(t)
	f.srv.OnAcknowledge(func(ctx context.Context, who *server.Identity, src *ua.NodeID, name, comment string) ua.StatusCode {
		return ua.StatusBadUserAccessDenied
	})
	admin, err := f.client(t, ua.SecurityPolicyURINone, "admin", "secret")
	require.NoError(t, err)
	ch, _ := subscribeEvents(t, admin, ua.NewNumericNodeID(0, id.Server), alarmFilter())
	require.NoError(t, f.srv.SetAlarm(server.Alarm{Source: f.id("Temp"), Name: "High", Active: true}))
	ev := nextEvent(t, ch, 2*time.Second)
	require.NotNil(t, ev)
	res := call(t, admin, ev[fConditionID].Value().(*ua.NodeID), ua.NewNumericNodeID(0, id.AcknowledgeableConditionType_Acknowledge),
		ev[fEventID].Value().([]byte), ua.NewLocalizedText(""))
	require.Equal(t, ua.StatusBadUserAccessDenied, res.StatusCode)
	require.False(t, f.srv.Alarms()[0].Acked)
}
