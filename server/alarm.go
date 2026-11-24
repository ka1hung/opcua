package server

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// Alarm is the state of an alarm condition (OPC 10000-9 §5.8.2) as the
// application reports it.
type Alarm struct {
	// Source is the node the alarm is about, e.g. a point's variable.
	Source *ua.NodeID
	// Name is the ConditionName, unique per source, e.g. "HighAlarm".
	Name string
	// Type is the alarm's event type; AlarmConditionType if nil. It must
	// be a subtype of AlarmConditionType.
	Type     *ua.NodeID
	Message  string
	Severity uint16
	Active   bool
	// Time is when the state changed; now if zero.
	Time time.Time
}

// AlarmState is an alarm as the server keeps it.
type AlarmState struct {
	Alarm
	ConditionID *ua.NodeID
	Acked       bool
	Retain      bool
	Comment     string
	AckedBy     string
}

// AcknowledgeFunc is called when a client acknowledges an alarm. A status
// that is not Good refuses the acknowledgement.
type AcknowledgeFunc func(ctx context.Context, who *Identity, source *ua.NodeID, name, comment string) ua.StatusCode

type condition struct {
	state       AlarmState
	lastSev     uint16
	lastEventID []byte
	// last is the newest event of the condition; ConditionRefresh sends
	// it again unchanged, so its EventId stays valid for Acknowledge.
	last       *eventData
	activeTime time.Time
	ackedTime  time.Time
}

type alarmManager struct {
	mu    sync.Mutex
	conds map[string]*condition // by condition node id
	onAck AcknowledgeFunc
}

var (
	typeAlarmCondition = ua.NewNumericNodeID(0, id.AlarmConditionType)
	refHasCondition    = ua.NewNumericNodeID(0, id.HasCondition)
)

func (s *Server) initAlarms() {
	s.alarms.conds = make(map[string]*condition)
	_ = s.SetMethodHandler(ua.NewNumericNodeID(0, id.AcknowledgeableConditionType_Acknowledge), s.acknowledgeMethod)
	for _, m := range []struct {
		id uint32
		h  MethodFunc
	}{{id.ConditionType_ConditionRefresh, s.conditionRefresh}, {id.ConditionType_ConditionRefresh2, s.conditionRefresh2}} {
		_ = s.SetMethodHandler(ua.NewNumericNodeID(0, m.id), m.h)
		// Refreshing changes nothing; anyone who may subscribe may call it.
		if n := s.space.Node(ua.NewNumericNodeID(0, m.id)); n != nil {
			n.mu.Lock()
			n.readOnlyCall = true
			n.mu.Unlock()
		}
	}
}

// OnAcknowledge sets the function called when a client acknowledges an
// alarm, for example to record who did it.
func (s *Server) OnAcknowledge(f AcknowledgeFunc) {
	s.alarms.mu.Lock()
	s.alarms.onAck = f
	s.alarms.mu.Unlock()
}

func conditionID(source *ua.NodeID, name string) *ua.NodeID {
	return ua.NewStringNodeID(source.Namespace(), propertyIDBase(source)+".Condition."+name)
}

// SetAlarm reports the state of an alarm. The first call for a source and
// name creates the condition; each call that changes its state, message
// or severity reports an event. A new activation must be acknowledged
// again; an alarm is retained, and sent on ConditionRefresh, while it is
// active or unacknowledged.
func (s *Server) SetAlarm(a Alarm) error {
	if a.Source == nil || a.Name == "" {
		return fmt.Errorf("server: alarm needs Source and Name")
	}
	if a.Type == nil {
		a.Type = typeAlarmCondition
	}
	if !s.space.isSubtype(a.Type, typeAlarmCondition) {
		return fmt.Errorf("server: %s is not an AlarmConditionType", a.Type)
	}
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	cid := conditionID(a.Source, a.Name)
	if err := s.ensureConditionNode(a, cid); err != nil {
		return err
	}

	s.alarms.mu.Lock()
	c := s.alarms.conds[key(cid)]
	if c == nil {
		if !a.Active {
			// An alarm that never became active reports nothing.
			s.alarms.mu.Unlock()
			return nil
		}
		c = &condition{state: AlarmState{ConditionID: cid, Acked: true}}
		s.alarms.conds[key(cid)] = c
	}
	prev := c.state
	changed := prev.Alarm.Active != a.Active || prev.Message != a.Message || prev.Severity != a.Severity || prev.Type == nil
	if !changed {
		s.alarms.mu.Unlock()
		return nil
	}
	c.lastSev = prev.Severity
	if a.Active && !prev.Alarm.Active {
		// A new activation needs a new acknowledgement.
		c.state.Acked = false
		c.state.Comment, c.state.AckedBy = "", ""
		c.activeTime = a.Time
	}
	if !a.Active && prev.Alarm.Active {
		c.activeTime = a.Time
	}
	c.state.Alarm = a
	c.state.Retain = a.Active || !c.state.Acked
	d := s.conditionEvent(c)
	if !c.state.Retain {
		delete(s.alarms.conds, key(cid))
	}
	s.alarms.mu.Unlock()

	s.deliver(d, nil)
	return nil
}

// ensureConditionNode adds the condition's node, an instance of the alarm
// type that clients call Acknowledge on.
func (s *Server) ensureConditionNode(a Alarm, cid *ua.NodeID) error {
	if s.space.Node(cid) != nil {
		return nil
	}
	if s.space.Node(a.Source) == nil {
		return fmt.Errorf("server: alarm source %s: %w", a.Source, ua.StatusBadNodeIDUnknown)
	}
	n := &Node{
		id:          cid,
		class:       ua.NodeClassObject,
		browseName:  &ua.QualifiedName{NamespaceIndex: cid.Namespace(), Name: a.Name},
		displayName: ua.NewLocalizedText(a.Name),
		description: ua.NewLocalizedText(""),
	}
	if err := s.space.add(n); err != nil && err != ua.StatusBadNodeIDExists {
		return err
	}
	s.space.addRef(a.Source, refHasCondition, cid)
	s.space.addRef(cid, refHasTypeDefinition, a.Type)
	return nil
}

// conditionEvent builds the event for a condition's current state (OPC
// 10000-9 §5.5, §5.7, §5.8). Called with alarms.mu held.
func (s *Server) conditionEvent(c *condition) *eventData {
	st := c.state
	d, err := s.eventData(&Event{
		Type:     st.Type,
		Source:   st.Source,
		Time:     st.Time,
		Message:  st.Message,
		Severity: st.Severity,
	})
	if err != nil {
		// The source was removed; report from the Server object.
		d, _ = s.eventData(&Event{Type: st.Type, Time: st.Time, Message: st.Message, Severity: st.Severity})
	}
	d.conditionID = st.ConditionID
	set := func(k string, v any) {
		if vv, err := ua.NewVariant(v); err == nil {
			d.fields[k] = vv
		}
	}
	activeText, ackedText := "Inactive", "Unacknowledged"
	if st.Active {
		activeText = "Active"
	}
	if st.Acked {
		ackedText = "Acknowledged"
	}
	set("ConditionClassId", ua.NewNumericNodeID(0, id.BaseConditionClassType))
	set("ConditionClassName", ua.NewLocalizedText("BaseConditionClass"))
	set("ConditionName", st.Name)
	set("BranchId", ua.NewTwoByteNodeID(0))
	set("Retain", st.Retain)
	set("EnabledState", ua.NewLocalizedText("Enabled"))
	set("EnabledState/Id", true)
	set("Quality", ua.StatusOK)
	set("LastSeverity", c.lastSev)
	set("Comment", ua.NewLocalizedText(st.Comment))
	set("ClientUserId", st.AckedBy)
	set("AckedState", ua.NewLocalizedText(ackedText))
	set("AckedState/Id", st.Acked)
	set("ActiveState", ua.NewLocalizedText(activeText))
	set("ActiveState/Id", st.Active)
	set("ActiveState/EffectiveDisplayName", ua.NewLocalizedText(activeText))
	if !c.activeTime.IsZero() {
		set("ActiveState/TransitionTime", c.activeTime)
	}
	if !c.ackedTime.IsZero() {
		set("AckedState/TransitionTime", c.ackedTime)
	}
	set("SuppressedOrShelved", false)
	c.lastEventID, _ = d.fields["EventId"].Value().([]byte)
	c.last = d
	return d
}

// Alarms returns the alarms the server keeps.
func (s *Server) Alarms() []AlarmState {
	s.alarms.mu.Lock()
	defer s.alarms.mu.Unlock()
	out := make([]AlarmState, 0, len(s.alarms.conds))
	for _, c := range s.alarms.conds {
		out = append(out, c.state)
	}
	return out
}

// AcknowledgeAlarm acknowledges an alarm on behalf of the application,
// e.g. from its own operator screen.
func (s *Server) AcknowledgeAlarm(source *ua.NodeID, name, comment, user string) error {
	st := s.acknowledge(conditionID(source, name), nil, comment, user)
	if st != ua.StatusOK {
		return st
	}
	return nil
}

func (s *Server) acknowledge(cid *ua.NodeID, eventID []byte, comment, user string) ua.StatusCode {
	s.alarms.mu.Lock()
	c := s.alarms.conds[key(cid)]
	if c == nil {
		s.alarms.mu.Unlock()
		return ua.StatusBadNodeIDUnknown
	}
	if eventID != nil && !bytes.Equal(eventID, c.lastEventID) {
		s.alarms.mu.Unlock()
		return ua.StatusBadEventIDUnknown
	}
	if c.state.Acked {
		s.alarms.mu.Unlock()
		return ua.StatusBadConditionBranchAlreadyAcked
	}
	c.state.Acked = true
	c.state.Comment = comment
	c.state.AckedBy = user
	c.ackedTime = time.Now()
	c.state.Retain = c.state.Active
	c.lastSev = c.state.Severity
	d := s.conditionEvent(c)
	if !c.state.Retain {
		// Inactive and acknowledged: nothing left to report on refresh.
		delete(s.alarms.conds, key(cid))
	}
	s.alarms.mu.Unlock()
	s.deliver(d, nil)
	return ua.StatusOK
}

// acknowledgeMethod is AcknowledgeableConditionType.Acknowledge
// (OPC 10000-9 §5.7.3): arguments EventId and Comment.
func (s *Server) acknowledgeMethod(ctx context.Context, who *Identity, object *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	eventID, _ := args[0].Value().([]byte)
	comment := ""
	if len(args) > 1 && args[1] != nil {
		if lt, ok := args[1].Value().(*ua.LocalizedText); ok && lt != nil {
			comment = lt.Text
		}
	}
	s.alarms.mu.Lock()
	c := s.alarms.conds[key(object)]
	f := s.alarms.onAck
	var src *ua.NodeID
	var name string
	st := ua.StatusOK
	switch {
	case c == nil:
		st = ua.StatusBadNodeIDUnknown
	case !bytes.Equal(eventID, c.lastEventID):
		st = ua.StatusBadEventIDUnknown
	case c.state.Acked:
		st = ua.StatusBadConditionBranchAlreadyAcked
	default:
		src, name = c.state.Source, c.state.Name
	}
	s.alarms.mu.Unlock()
	if st != ua.StatusOK {
		// The application hears only of acknowledgements that can succeed.
		return nil, st
	}
	if f != nil {
		if st := f(ctx, who, src, name, comment); !isGood(st) {
			return nil, st
		}
	}
	user := who.UserName
	if who.Certificate != nil {
		user = who.Certificate.Subject.CommonName
	}
	return nil, s.acknowledge(object, eventID, comment, user)
}

// conditionRefresh is ConditionType.ConditionRefresh (OPC 10000-9
// §5.5.7): it sends the retained conditions to the event items of a
// subscription, framed by RefreshStart and RefreshEnd events.
func (s *Server) conditionRefresh(ctx context.Context, who *Identity, object *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	subID, ok := args[0].Value().(uint32)
	if !ok {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	sub := s.subs.get(subID, sessionFrom(ctx))
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	sub.mu.Lock()
	var items []*monitoredItem
	for _, it := range sub.items {
		if it.isEvent() {
			items = append(items, it)
		}
	}
	sub.mu.Unlock()
	s.refresh(items)
	return nil, ua.StatusOK
}

// conditionRefresh2 is ConditionType.ConditionRefresh2: the same for one
// monitored item.
func (s *Server) conditionRefresh2(ctx context.Context, who *Identity, object *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	subID, ok1 := args[0].Value().(uint32)
	itemID, ok2 := args[1].Value().(uint32)
	if !ok1 || !ok2 {
		return nil, ua.StatusBadInvalidArgument
	}
	sub := s.subs.get(subID, sessionFrom(ctx))
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	sub.mu.Lock()
	it := sub.items[itemID]
	sub.mu.Unlock()
	if it == nil || !it.isEvent() {
		return nil, ua.StatusBadMonitoredItemIDInvalid
	}
	s.refresh([]*monitoredItem{it})
	return nil, ua.StatusOK
}

func (s *Server) refresh(items []*monitoredItem) {
	start, _ := s.eventData(&Event{Type: ua.NewNumericNodeID(0, id.RefreshStartEventType)})
	end, _ := s.eventData(&Event{Type: ua.NewNumericNodeID(0, id.RefreshEndEventType)})
	s.alarms.mu.Lock()
	var events []*eventData
	for _, c := range s.alarms.conds {
		if c.state.Retain {
			d := c.last
			if d == nil {
				d = s.conditionEvent(c)
			}
			events = append(events, d)
		}
	}
	s.alarms.mu.Unlock()
	for _, it := range items {
		s.deliver(start, it)
		for _, d := range events {
			// Only the conditions this item's notifier reports.
			if d.notifiers[key(it.node.id)] {
				s.deliver(d, it)
			}
		}
		s.deliver(end, it)
	}
}

type ctxKey int

const sessionKey ctxKey = 0

func withSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionKey, sess)
}

// sessionFrom returns the session of the request a handler runs for.
func sessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey).(*Session)
	return s
}
