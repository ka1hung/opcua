package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// Event is an event or an alarm (condition) event.
type Event struct {
	EventID    []byte
	EventType  string // node id of the event type, e.g. i=2915 for AlarmConditionType
	Source     string // node id of the source, e.g. the point the alarm is about
	SourceName string
	Time       time.Time
	Message    string
	Severity   uint16 // 1 (lowest) .. 1000 (highest)

	// Set for alarms and other conditions.
	ConditionID   string
	ConditionName string
	Retain        bool // the condition is still of interest: active or not yet acknowledged
	Active        bool
	Acked         bool

	// RefreshStart and RefreshEnd mark the beginning and end of the
	// conditions a ConditionRefresh sends again.
	RefreshStart bool
	RefreshEnd   bool
}

// IsCondition reports whether the event is about an alarm or another
// condition, which can be acknowledged.
func (e Event) IsCondition() bool { return e.ConditionID != "" }

// The fields every event is asked for, in this order.
var eventFields = []struct {
	typ  uint32
	path string // "" with typ ConditionType asks for the ConditionId
}{
	{id.BaseEventType, "EventId"},
	{id.BaseEventType, "EventType"},
	{id.BaseEventType, "SourceNode"},
	{id.BaseEventType, "SourceName"},
	{id.BaseEventType, "Time"},
	{id.BaseEventType, "Message"},
	{id.BaseEventType, "Severity"},
	{id.ConditionType, ""},
	{id.ConditionType, "ConditionName"},
	{id.ConditionType, "Retain"},
	{id.AlarmConditionType, "ActiveState/Id"},
	{id.AcknowledgeableConditionType, "AckedState/Id"},
}

func eventFilter() *ua.EventFilter {
	f := &ua.EventFilter{}
	for _, ef := range eventFields {
		op := &ua.SimpleAttributeOperand{TypeDefinitionID: ua.NewNumericNodeID(0, ef.typ), AttributeID: ua.AttributeIDValue}
		if ef.path == "" {
			op.AttributeID = ua.AttributeIDNodeID
		} else {
			for _, p := range splitPath(ef.path) {
				op.BrowsePath = append(op.BrowsePath, &ua.QualifiedName{Name: p})
			}
		}
		f.SelectClauses = append(f.SelectClauses, op)
	}
	return f
}

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	return append(out, p[start:])
}

func parseEvent(fields []*ua.Variant) Event {
	var e Event
	get := func(i int) any {
		if i < len(fields) && fields[i] != nil {
			return fields[i].Value()
		}
		return nil
	}
	e.EventID, _ = get(0).([]byte)
	if t, ok := get(1).(*ua.NodeID); ok && t != nil {
		e.EventType = t.String()
		e.RefreshStart = t.Namespace() == 0 && t.IntID() == id.RefreshStartEventType
		e.RefreshEnd = t.Namespace() == 0 && t.IntID() == id.RefreshEndEventType
	}
	if s, ok := get(2).(*ua.NodeID); ok && s != nil {
		e.Source = s.String()
	}
	e.SourceName, _ = get(3).(string)
	e.Time, _ = get(4).(time.Time)
	if m, ok := get(5).(*ua.LocalizedText); ok && m != nil {
		e.Message = m.Text
	}
	e.Severity, _ = get(6).(uint16)
	if c, ok := get(7).(*ua.NodeID); ok && c != nil {
		e.ConditionID = c.String()
	}
	e.ConditionName, _ = get(8).(string)
	e.Retain, _ = get(9).(bool)
	e.Active, _ = get(10).(bool)
	e.Acked, _ = get(11).(bool)
	return e
}

// EventSubscription delivers events and alarms.
type EventSubscription struct {
	sub    *opcua.Subscription
	c      *Client
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

// ServerObject is the node id of the Server object, which notifies all
// events of a server.
const ServerObject = "i=2253"

// SubscribeEvents reports the events and alarms a notifier sends to f,
// from one goroutine. The notifier is an object with events, such as
// ServerObject (all events, the default when empty) or an area. Call
// Refresh to receive the alarms that were already active.
func (c *Client) SubscribeEvents(ctx context.Context, notifier string, interval time.Duration, f func(Event)) (*EventSubscription, error) {
	if notifier == "" {
		notifier = ServerObject
	}
	nid, err := c.parse(notifier)
	if err != nil {
		return nil, err
	}
	ch := make(chan *opcua.PublishNotificationData, 256)
	sctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	sub, err := c.c.Subscribe(sctx, &opcua.SubscriptionParameters{Interval: interval}, ch)
	if err != nil {
		return nil, fmt.Errorf("client: subscribe events: %w", err)
	}
	req := opcua.NewMonitoredItemCreateRequestWithDefaults(nid, ua.AttributeIDEventNotifier, 1)
	req.RequestedParameters.Filter = ua.NewExtensionObject(eventFilter())
	req.RequestedParameters.QueueSize = 1000
	resp, err := sub.Monitor(sctx, ua.TimestampsToReturnNeither, req)
	if err == nil && (len(resp.Results) != 1 || resp.Results[0].StatusCode != ua.StatusOK) {
		err = ua.StatusBadUnexpectedError
		if len(resp.Results) == 1 {
			err = resp.Results[0].StatusCode
		}
	}
	if err != nil {
		_ = sub.Cancel(context.Background())
		return nil, fmt.Errorf("client: subscribe events of %s: %w", notifier, err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	s := &EventSubscription{sub: sub, c: c, cancel: runCancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			select {
			case <-runCtx.Done():
				return
			case n := <-ch:
				if n == nil || n.Error != nil {
					continue
				}
				list, ok := n.Value.(*ua.EventNotificationList)
				if !ok {
					continue
				}
				for _, ev := range list.Events {
					if ev != nil {
						f(parseEvent(ev.EventFields))
					}
				}
			}
		}
	}()
	return s, nil
}

// Refresh asks the server to send every alarm that is still of interest
// again (ConditionRefresh), between an event with RefreshStart and one
// with RefreshEnd. Use it after subscribing or reconnecting to learn the
// alarms that were already active.
func (s *EventSubscription) Refresh(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, s.c.timeout)
	defer cancel()
	res, err := s.c.c.Call(cctx, &ua.CallMethodRequest{
		ObjectID:       ua.NewNumericNodeID(0, id.ConditionType),
		MethodID:       ua.NewNumericNodeID(0, id.ConditionType_ConditionRefresh),
		InputArguments: []*ua.Variant{ua.MustVariant(s.sub.SubscriptionID)},
	})
	if err != nil {
		return fmt.Errorf("client: condition refresh: %w", err)
	}
	if res.StatusCode != ua.StatusOK {
		return &CallError{Method: "ConditionRefresh", Status: res.StatusCode, Args: res.InputArgumentResults}
	}
	return nil
}

// Close ends the subscription.
func (s *EventSubscription) Close() error {
	var err error
	s.once.Do(func() {
		s.cancel()
		<-s.done
		ctx, cancel := context.WithTimeout(context.Background(), s.c.timeout)
		defer cancel()
		err = s.sub.Cancel(ctx)
	})
	return err
}

var errNotCondition = errors.New("client: the event is not an alarm or condition")

// Acknowledge acknowledges the alarm an event reports, with a comment
// the server records. Only the newest event of an alarm can be
// acknowledged; an older one is refused with Bad_EventIdUnknown.
func (c *Client) Acknowledge(ctx context.Context, ev Event, comment string) error {
	if !ev.IsCondition() {
		return errNotCondition
	}
	cid, err := c.parse(ev.ConditionID)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	res, err := c.c.Call(cctx, &ua.CallMethodRequest{
		ObjectID: cid,
		MethodID: ua.NewNumericNodeID(0, id.AcknowledgeableConditionType_Acknowledge),
		InputArguments: []*ua.Variant{
			ua.MustVariant(ev.EventID),
			ua.MustVariant(ua.NewLocalizedText(comment)),
		},
	})
	if err != nil {
		return fmt.Errorf("client: acknowledge %s: %w", ev.ConditionID, err)
	}
	if res.StatusCode != ua.StatusOK {
		return &CallError{Method: "Acknowledge", Status: res.StatusCode, Args: res.InputArgumentResults}
	}
	return nil
}
