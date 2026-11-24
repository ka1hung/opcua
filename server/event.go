package server

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// Event is an event to report to clients (OPC 10000-5 §6.4.2).
type Event struct {
	// Type is the event type; BaseEventType if nil.
	Type *ua.NodeID
	// Source is the node the event is about. Its notifiers, up to the
	// Server object, report the event.
	Source *ua.NodeID
	// Time is when the event happened; now if zero.
	Time     time.Time
	Message  string
	Severity uint16
	// Fields holds further fields by browse path, e.g. "ConditionName" or
	// "ActiveState/Id". Values are Go values or *ua.Variant.
	Fields map[string]any
}

// eventData is an event as filters see it.
type eventData struct {
	typ         *ua.NodeID
	conditionID *ua.NodeID
	fields      map[string]*ua.Variant
	notifiers   map[string]bool
}

func (e *eventData) field(path string) *ua.Variant {
	if v, ok := e.fields[path]; ok {
		return v
	}
	return nil
}

// eventSinkSet holds the event monitored items of the server.
type eventSinkSet struct {
	mu    sync.Mutex
	items map[*monitoredItem]struct{}
}

func (e *eventSinkSet) add(it *monitoredItem) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.items == nil {
		e.items = make(map[*monitoredItem]struct{})
	}
	e.items[it] = struct{}{}
}

func (e *eventSinkSet) remove(it *monitoredItem) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.items, it)
}

func (e *eventSinkSet) list() []*monitoredItem {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*monitoredItem, 0, len(e.items))
	for it := range e.items {
		out = append(out, it)
	}
	return out
}

var typeBaseEvent = ua.NewNumericNodeID(0, id.BaseEventType)

// FireEvent reports an event to the clients that subscribed to events of
// its source or of a notifier above it.
func (s *Server) FireEvent(ev *Event) error {
	data, err := s.eventData(ev)
	if err != nil {
		return err
	}
	s.deliver(data, nil)
	return nil
}

func (s *Server) eventData(ev *Event) (*eventData, error) {
	typ := ev.Type
	if typ == nil {
		typ = typeBaseEvent
	}
	if !s.space.isSubtype(typ, typeBaseEvent) {
		return nil, fmt.Errorf("server: %s is not an event type", typ)
	}
	source := ev.Source
	if source == nil {
		source = ua.NewNumericNodeID(0, id.Server)
	}
	src := s.space.Node(source)
	if src == nil {
		return nil, fmt.Errorf("server: event source %s: %w", source, ua.StatusBadNodeIDUnknown)
	}
	now := time.Now()
	t := ev.Time
	if t.IsZero() {
		t = now
	}
	sourceName := ""
	if bn := src.BrowseName(); bn != nil {
		sourceName = bn.Name
	}
	d := &eventData{typ: typ, fields: map[string]*ua.Variant{}}
	set := func(k string, v any) {
		if vv, ok := v.(*ua.Variant); ok {
			d.fields[k] = vv
			return
		}
		if vv, err := ua.NewVariant(v); err == nil {
			d.fields[k] = vv
		}
	}
	set("EventId", randomBytes(16))
	set("EventType", typ)
	set("SourceNode", source)
	set("SourceName", sourceName)
	set("Time", t)
	set("ReceiveTime", now)
	set("Message", ua.NewLocalizedText(ev.Message))
	set("Severity", ev.Severity)
	for k, v := range ev.Fields {
		set(k, v)
	}
	d.notifiers = s.notifiersOf(source)
	return d, nil
}

// notifiersOf returns the source and every node that reports its events:
// the nodes above it through inverse hierarchical references, which
// include HasNotifier and HasEventSource as well as HasComponent and
// Organizes, so an area object with events reports the alarms of the
// points below it. The Server object reports every event.
func (s *Server) notifiersOf(source *ua.NodeID) map[string]bool {
	out := map[string]bool{key(source): true, key(ua.NewNumericNodeID(0, id.Server)): true}
	hierarchical := ua.NewNumericNodeID(0, id.HierarchicalReferences)
	queue := []*ua.NodeID{source}
	for len(queue) > 0 && len(out) < 1024 {
		cur := queue[0]
		queue = queue[1:]
		n := s.space.Node(cur)
		if n == nil {
			continue
		}
		for _, r := range s.space.refsOf(n) {
			if r.forward || !s.space.isSubtype(r.refType, hierarchical) {
				continue
			}
			if k := key(r.target); !out[k] {
				out[k] = true
				queue = append(queue, r.target)
			}
		}
	}
	return out
}

// deliver hands an event to the matching event items; with only set, to
// that item alone (for ConditionRefresh).
func (s *Server) deliver(d *eventData, only *monitoredItem) {
	for _, it := range s.eventSinks.list() {
		if only != nil && it != only {
			continue
		}
		if only == nil && !d.notifiers[key(it.node.id)] {
			continue
		}
		it.offerEvent(d)
	}
}

// offerEvent applies the item's filter and queues the selected fields.
func (it *monitoredItem) offerEvent(d *eventData) {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.mode == ua.MonitoringModeDisabled || it.eventFilter == nil {
		return
	}
	srv := it.sub.srv
	if wc := it.eventFilter.WhereClause; wc != nil && len(wc.Elements) > 0 {
		if !srv.evalFilter(wc, 0, d, 0).truthy() {
			return
		}
	}
	fields := make([]*ua.Variant, len(it.eventFilter.SelectClauses))
	for i, sc := range it.eventFilter.SelectClauses {
		fields[i] = srv.selectField(sc, d)
	}
	if len(it.events) >= it.queueSize {
		if it.discardOldest {
			it.events = it.events[1:]
		} else {
			return
		}
	}
	it.events = append(it.events, &ua.EventFieldList{EventFields: fields})
}

// selectField resolves a select clause against an event.
func (s *Server) selectField(sc *ua.SimpleAttributeOperand, d *eventData) *ua.Variant {
	if sc == nil {
		return nullVariant()
	}
	if sc.TypeDefinitionID != nil && !isNull(sc.TypeDefinitionID) && !s.space.isSubtype(d.typ, sc.TypeDefinitionID) {
		return nullVariant()
	}
	if sc.AttributeID == ua.AttributeIDNodeID && len(sc.BrowsePath) == 0 {
		// The ConditionId of a condition event (OPC 10000-9 §5.5.2).
		if d.conditionID != nil {
			v, _ := ua.NewVariant(d.conditionID)
			return v
		}
		return nullVariant()
	}
	if v := d.field(browsePath(sc.BrowsePath)); v != nil {
		return v
	}
	return nullVariant()
}

func browsePath(p []*ua.QualifiedName) string {
	parts := make([]string, len(p))
	for i, q := range p {
		if q != nil {
			parts[i] = q.Name
		}
	}
	return strings.Join(parts, "/")
}

// setupEventItem prepares an event monitored item (OPC 10000-4 §5.12.1.6).
func (s *Server) setupEventItem(it *monitoredItem, n *Node, who *Identity, f *ua.ExtensionObject) (*ua.ExtensionObject, ua.StatusCode) {
	if n.class != ua.NodeClassObject && n.class != ua.NodeClassView {
		return nil, ua.StatusBadAttributeIDInvalid
	}
	n.mu.RLock()
	en := n.eventNotifier
	n.mu.RUnlock()
	if en&EventNotifierSubscribeToEvents == 0 {
		return nil, ua.StatusBadNotSupported
	}
	if it.indexRange != "" {
		return nil, ua.StatusBadIndexRangeInvalid
	}
	return s.setEventFilter(it, f)
}

// setEventFilter checks an EventFilter and applies it.
func (s *Server) setEventFilter(it *monitoredItem, f *ua.ExtensionObject) (*ua.ExtensionObject, ua.StatusCode) {
	if f == nil || f.Value == nil {
		return nil, ua.StatusBadEventFilterInvalid
	}
	ef, ok := f.Value.(*ua.EventFilter)
	if !ok {
		return nil, ua.StatusBadFilterNotAllowed
	}
	res := &ua.EventFilterResult{
		SelectClauseResults: make([]ua.StatusCode, len(ef.SelectClauses)),
		WhereClauseResult:   &ua.ContentFilterResult{},
	}
	bad := len(ef.SelectClauses) == 0
	for i, sc := range ef.SelectClauses {
		if st := s.checkSelect(sc); st != ua.StatusOK {
			res.SelectClauseResults[i] = st
			bad = true
		}
	}
	if wc := ef.WhereClause; wc != nil {
		er, ok := s.checkWhere(wc)
		res.WhereClauseResult.ElementResults = er
		bad = bad || !ok
	}
	if bad {
		return ua.NewExtensionObject(res), ua.StatusBadEventFilterInvalid
	}
	it.mu.Lock()
	it.eventFilter = ef
	it.mu.Unlock()
	if allGood(res) {
		return nil, ua.StatusOK
	}
	return ua.NewExtensionObject(res), ua.StatusOK
}

func allGood(r *ua.EventFilterResult) bool {
	for _, st := range r.SelectClauseResults {
		if st != ua.StatusOK {
			return false
		}
	}
	return len(r.WhereClauseResult.ElementResults) == 0
}

func (s *Server) checkSelect(sc *ua.SimpleAttributeOperand) ua.StatusCode {
	if sc == nil {
		return ua.StatusBadFilterOperandInvalid
	}
	if sc.AttributeID != ua.AttributeIDValue && sc.AttributeID != ua.AttributeIDNodeID {
		return ua.StatusBadAttributeIDInvalid
	}
	if sc.TypeDefinitionID != nil && !isNull(sc.TypeDefinitionID) && !s.space.isSubtype(sc.TypeDefinitionID, typeBaseEvent) {
		return ua.StatusBadTypeDefinitionInvalid
	}
	if sc.AttributeID == ua.AttributeIDValue && len(sc.BrowsePath) == 0 {
		return ua.StatusBadBrowseNameInvalid
	}
	return ua.StatusOK
}

// operandCounts gives the operand count of each supported operator; -1
// means two or more.
var operandCounts = map[ua.FilterOperator]int{
	ua.FilterOperatorEquals:             2,
	ua.FilterOperatorIsNull:             1,
	ua.FilterOperatorGreaterThan:        2,
	ua.FilterOperatorLessThan:           2,
	ua.FilterOperatorGreaterThanOrEqual: 2,
	ua.FilterOperatorLessThanOrEqual:    2,
	ua.FilterOperatorLike:               2,
	ua.FilterOperatorNot:                1,
	ua.FilterOperatorBetween:            3,
	ua.FilterOperatorInList:             -1,
	ua.FilterOperatorAnd:                2,
	ua.FilterOperatorOr:                 2,
	ua.FilterOperatorOfType:             1,
}

// checkWhere validates a where clause before it is used: supported
// operators, operand counts and kinds, and element references that only
// point forward, so evaluation always ends (OPC 10000-4 §7.7).
func (s *Server) checkWhere(cf *ua.ContentFilter) ([]*ua.ContentFilterElementResult, bool) {
	results := make([]*ua.ContentFilterElementResult, len(cf.Elements))
	ok := true
	for i, el := range cf.Elements {
		r := &ua.ContentFilterElementResult{StatusCode: ua.StatusOK}
		results[i] = r
		if el == nil {
			r.StatusCode = ua.StatusBadFilterOperandInvalid
			ok = false
			continue
		}
		want, supported := operandCounts[el.FilterOperator]
		if !supported {
			r.StatusCode = ua.StatusBadFilterOperatorUnsupported
			ok = false
			continue
		}
		n := len(el.FilterOperands)
		if want >= 0 && n != want || want < 0 && n < 2 {
			r.StatusCode = ua.StatusBadFilterOperandCountMismatch
			ok = false
			continue
		}
		r.OperandStatusCodes = make([]ua.StatusCode, n)
		for j, op := range el.FilterOperands {
			st := ua.StatusOK
			switch o := operandValue(op).(type) {
			case *ua.ElementOperand:
				if int(o.Index) <= i || int(o.Index) >= len(cf.Elements) {
					st = ua.StatusBadFilterOperandInvalid
				}
			case *ua.LiteralOperand:
				if o.Value == nil {
					st = ua.StatusBadFilterOperandInvalid
				}
				if el.FilterOperator == ua.FilterOperatorOfType {
					if nid, isID := o.Value.Value().(*ua.NodeID); !isID || !s.space.isSubtype(nid, typeBaseEvent) {
						st = ua.StatusBadFilterOperandInvalid
					}
				}
			case *ua.SimpleAttributeOperand:
				st = s.checkSelect(o)
			default:
				st = ua.StatusBadFilterOperandInvalid
			}
			r.OperandStatusCodes[j] = st
			if st != ua.StatusOK {
				r.StatusCode = ua.StatusBadFilterOperandInvalid
				ok = false
			}
		}
	}
	if ok {
		return nil, true
	}
	return results, false
}

func operandValue(eo *ua.ExtensionObject) any {
	if eo == nil {
		return nil
	}
	return eo.Value
}

// filterValue is the result of evaluating an operand: a value, or a
// Boolean for operators.
type filterValue struct{ v any }

func (f filterValue) truthy() bool {
	b, ok := f.v.(bool)
	return ok && b
}

const maxFilterDepth = 64

// evalFilter evaluates element i of a validated filter.
func (s *Server) evalFilter(cf *ua.ContentFilter, i int, d *eventData, depth int) filterValue {
	if depth > maxFilterDepth || i >= len(cf.Elements) {
		return filterValue{false}
	}
	el := cf.Elements[i]
	op := func(j int) filterValue { return s.operand(cf, el.FilterOperands[j], d, depth+1) }
	switch el.FilterOperator {
	case ua.FilterOperatorAnd:
		return filterValue{op(0).truthy() && op(1).truthy()}
	case ua.FilterOperatorOr:
		return filterValue{op(0).truthy() || op(1).truthy()}
	case ua.FilterOperatorNot:
		return filterValue{!op(0).truthy()}
	case ua.FilterOperatorIsNull:
		return filterValue{op(0).v == nil}
	case ua.FilterOperatorEquals:
		c, ok := compare(op(0).v, op(1).v)
		return filterValue{ok && c == 0}
	case ua.FilterOperatorGreaterThan:
		c, ok := compare(op(0).v, op(1).v)
		return filterValue{ok && c > 0}
	case ua.FilterOperatorLessThan:
		c, ok := compare(op(0).v, op(1).v)
		return filterValue{ok && c < 0}
	case ua.FilterOperatorGreaterThanOrEqual:
		c, ok := compare(op(0).v, op(1).v)
		return filterValue{ok && c >= 0}
	case ua.FilterOperatorLessThanOrEqual:
		c, ok := compare(op(0).v, op(1).v)
		return filterValue{ok && c <= 0}
	case ua.FilterOperatorBetween:
		v := op(0).v
		lo, ok1 := compare(v, op(1).v)
		hi, ok2 := compare(v, op(2).v)
		return filterValue{ok1 && ok2 && lo >= 0 && hi <= 0}
	case ua.FilterOperatorInList:
		v := op(0).v
		for j := 1; j < len(el.FilterOperands); j++ {
			if c, ok := compare(v, op(j).v); ok && c == 0 {
				return filterValue{true}
			}
		}
		return filterValue{false}
	case ua.FilterOperatorLike:
		str, ok1 := op(0).v.(string)
		pat, ok2 := op(1).v.(string)
		return filterValue{ok1 && ok2 && likeMatch(str, pat)}
	case ua.FilterOperatorOfType:
		lit, _ := operandValue(el.FilterOperands[0]).(*ua.LiteralOperand)
		if lit == nil || lit.Value == nil {
			return filterValue{false}
		}
		t, _ := lit.Value.Value().(*ua.NodeID)
		return filterValue{t != nil && s.space.isSubtype(d.typ, t)}
	}
	return filterValue{false}
}

func (s *Server) operand(cf *ua.ContentFilter, eo *ua.ExtensionObject, d *eventData, depth int) filterValue {
	switch o := operandValue(eo).(type) {
	case *ua.ElementOperand:
		return s.evalFilter(cf, int(o.Index), d, depth)
	case *ua.LiteralOperand:
		if o.Value == nil {
			return filterValue{nil}
		}
		return filterValue{o.Value.Value()}
	case *ua.SimpleAttributeOperand:
		v := s.selectField(o, d)
		if v == nil {
			return filterValue{nil}
		}
		return filterValue{v.Value()}
	}
	return filterValue{nil}
}

// compare orders two filter values: numbers by value, strings, Booleans,
// times and node ids by equality or order where defined.
func compare(a, b any) (int, bool) {
	if a == nil || b == nil {
		return 0, false
	}
	if x, ok := toFloat(a); ok {
		y, ok := toFloat(b)
		if !ok {
			return 0, false
		}
		switch {
		case x < y:
			return -1, true
		case x > y:
			return 1, true
		}
		return 0, true
	}
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		if !ok {
			return 0, false
		}
		return strings.Compare(x, y), true
	case bool:
		y, ok := b.(bool)
		if !ok {
			return 0, false
		}
		if x == y {
			return 0, true
		}
		if !x {
			return -1, true
		}
		return 1, true
	case time.Time:
		y, ok := b.(time.Time)
		if !ok {
			return 0, false
		}
		return x.Compare(y), true
	case *ua.NodeID:
		y, ok := b.(*ua.NodeID)
		if !ok {
			return 0, false
		}
		if sameID(x, y) {
			return 0, true
		}
		return 1, false
	case *ua.LocalizedText:
		if y, ok := b.(string); ok {
			return strings.Compare(x.Text, y), true
		}
		if y, ok := b.(*ua.LocalizedText); ok {
			return strings.Compare(x.Text, y.Text), true
		}
	}
	if reflect.DeepEqual(a, b) {
		return 0, true
	}
	return 0, false
}

// likeMatch implements the Like operator's patterns (OPC 10000-4 Table
// 117): % any run, _ any character, [] a set, [^] a negated set, and \ to
// escape.
func likeMatch(s, pattern string) bool {
	var re strings.Builder
	re.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '%':
			re.WriteString(".*")
		case '_':
			re.WriteString(".")
		case '\\':
			if i+1 < len(pattern) {
				i++
				re.WriteString(regexp.QuoteMeta(string(pattern[i])))
			}
		case '[':
			j := strings.IndexByte(pattern[i:], ']')
			if j < 0 {
				re.WriteString(regexp.QuoteMeta("["))
				continue
			}
			set := pattern[i+1 : i+j]
			if strings.HasPrefix(set, "^") {
				re.WriteString("[^" + regexp.QuoteMeta(set[1:]) + "]")
			} else {
				re.WriteString("[" + regexp.QuoteMeta(set) + "]")
			}
			i += j
		default:
			re.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	re.WriteString("$")
	ok, err := regexp.MatchString(re.String(), s)
	return err == nil && ok
}
