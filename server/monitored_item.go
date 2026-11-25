package server

import (
	"context"
	"math"
	"reflect"
	"sync"
	"time"

	"github.com/ka1hung/opcua/ua"
)

// Data value InfoBits (OPC 10000-4 §7.39.1).
const (
	statusInfoTypeDataValue = 0x400
	statusOverflow          = 0x80
)

// monitoredItem samples one attribute of a node, or receives the events
// of a notifier (OPC 10000-4 §5.12.1).
type monitoredItem struct {
	sub  *subscription
	id   uint32
	node *Node
	who  *Identity

	attr       ua.AttributeID
	indexRange string
	ttr        ua.TimestampsToReturn

	mu            sync.Mutex
	clientHandle  uint32
	mode          ua.MonitoringMode
	sampling      time.Duration
	queueSize     int
	discardOldest bool
	filter        *ua.DataChangeFilter
	deadband      float64 // absolute deadband derived from the filter
	pushed        bool    // values arrive through Node.setValue

	queue      []*ua.DataValue
	last       *ua.DataValue
	nextSample time.Time

	// events
	eventFilter *ua.EventFilter
	events      []*ua.EventFieldList
}

func (it *monitoredItem) isEvent() bool { return it.attr == ua.AttributeIDEventNotifier }

// onValue receives a new value of a pushed item.
func (it *monitoredItem) onValue(dv *ua.DataValue) {
	// A pushed value bypasses readAttribute, so the user's read access is
	// applied here, for every value: a CanRead that turns false after the
	// item was created stops the values, and the client gets
	// Bad_UserAccessDenied in their place (OPC 10000-4 §5.12.2.2). The
	// callback runs outside the item's lock.
	if !it.mayReadValue() {
		dv = &ua.DataValue{Status: ua.StatusBadUserAccessDenied, ServerTimestamp: time.Now()}
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	it.offerLocked(dv)
}

// mayReadValue reports whether the item's user may still read the value
// of its node.
func (it *monitoredItem) mayReadValue() bool {
	if it.attr != ua.AttributeIDValue || it.sub == nil || it.sub.srv == nil {
		return true
	}
	return it.sub.srv.userAccessLevel(it.node, it.who)&AccessLevelCurrentRead != 0
}

// offerLocked queues dv if it is a change under the item's filter.
func (it *monitoredItem) offerLocked(dv *ua.DataValue) {
	if it.mode == ua.MonitoringModeDisabled {
		return
	}
	if it.indexRange != "" && dv.Value != nil {
		v, st := applyIndexRange(dv.Value, it.indexRange)
		c := *dv
		if st != ua.StatusOK {
			c.Value, c.Status = nil, st
		} else {
			c.Value = v
		}
		dv = &c
	}
	if it.last != nil && !it.changed(it.last, dv) {
		return
	}
	it.last = dv
	c := withTimestamps(dv, it.ttr)
	if len(it.queue) >= it.queueSize {
		if it.discardOldest {
			it.queue = it.queue[1:]
			if it.queueSize > 1 && len(it.queue) > 0 {
				it.queue[0] = overflowed(it.queue[0])
			}
		} else {
			it.queue = it.queue[:len(it.queue)-1]
			if it.queueSize > 1 {
				c = overflowed(c)
			}
		}
	}
	it.queue = append(it.queue, c)
}

func overflowed(dv *ua.DataValue) *ua.DataValue {
	c := *dv
	c.Status = ua.StatusCode(uint32(c.Status) | statusInfoTypeDataValue | statusOverflow)
	c.UpdateMask()
	return &c
}

// changed applies the DataChangeFilter (OPC 10000-4 §7.22.2).
func (it *monitoredItem) changed(old, cur *ua.DataValue) bool {
	if old.Status != cur.Status {
		return true
	}
	trigger := ua.DataChangeTriggerStatusValue
	if it.filter != nil {
		trigger = it.filter.Trigger
	}
	if trigger == ua.DataChangeTriggerStatus {
		return false
	}
	if trigger == ua.DataChangeTriggerStatusValueTimestamp && !old.SourceTimestamp.Equal(cur.SourceTimestamp) {
		return true
	}
	var a, b any
	if old.Value != nil {
		a = old.Value.Value()
	}
	if cur.Value != nil {
		b = cur.Value.Value()
	}
	if it.filter != nil && it.filter.DeadbandType != uint32(ua.DeadbandTypeNone) {
		return exceedsDeadband(a, b, it.deadband)
	}
	return !reflect.DeepEqual(a, b)
}

// exceedsDeadband reports whether a numeric value, or any element of a
// numeric array, moved by more than the deadband.
func exceedsDeadband(a, b any, deadband float64) bool {
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	if !av.IsValid() || !bv.IsValid() || av.Type() != bv.Type() {
		return true
	}
	if av.Kind() == reflect.Slice {
		if av.Len() != bv.Len() {
			return true
		}
		for i := 0; i < av.Len(); i++ {
			if exceedsDeadband(av.Index(i).Interface(), bv.Index(i).Interface(), deadband) {
				return true
			}
		}
		return false
	}
	x, ok1 := toFloat(a)
	y, ok2 := toFloat(b)
	if !ok1 || !ok2 {
		return !reflect.DeepEqual(a, b)
	}
	return math.Abs(x-y) > deadband
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int8:
		return float64(x), true
	case uint8:
		return float64(x), true
	case int16:
		return float64(x), true
	case uint16:
		return float64(x), true
	case int32:
		return float64(x), true
	case uint32:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case float32:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// sample reads a polled item when its sampling interval has passed.
func (it *monitoredItem) sample(now time.Time) {
	it.mu.Lock()
	if it.pushed || it.isEvent() || it.mode == ua.MonitoringModeDisabled || now.Before(it.nextSample) {
		it.mu.Unlock()
		return
	}
	it.nextSample = now.Add(it.sampling)
	it.mu.Unlock()

	dv := it.read()
	it.mu.Lock()
	it.offerLocked(dv)
	it.mu.Unlock()
}

func (it *monitoredItem) read() *ua.DataValue {
	srv := it.sub.srv
	dv := srv.readAttribute(it.who, &ua.ReadValueID{NodeID: it.node.id, AttributeID: it.attr}, ua.TimestampsToReturnBoth)
	if it.attr != ua.AttributeIDValue && dv.Status == ua.StatusOK && dv.SourceTimestamp.IsZero() {
		dv.ServerTimestamp = time.Now()
	}
	return dv
}

// sendCurrent queues the current value even if it did not change, as
// TransferSubscriptions with SendInitialValues asks.
func (it *monitoredItem) sendCurrent() {
	if it.isEvent() {
		return
	}
	dv := it.read()
	it.mu.Lock()
	it.last = nil
	it.offerLocked(dv)
	it.mu.Unlock()
}

func (it *monitoredItem) hasData() bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.mode != ua.MonitoringModeReporting {
		return false
	}
	return len(it.queue) > 0 || len(it.events) > 0
}

// drain removes up to room notifications (all with room < 0).
func (it *monitoredItem) drain(room int) (changes []*ua.MonitoredItemNotification, events []*ua.EventFieldList, more bool) {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.mode != ua.MonitoringModeReporting {
		return nil, nil, false
	}
	n := len(it.queue)
	if room >= 0 && n > room {
		n = room
	}
	for _, dv := range it.queue[:n] {
		changes = append(changes, &ua.MonitoredItemNotification{ClientHandle: it.clientHandle, Value: dv})
	}
	it.queue = it.queue[n:]
	if room >= 0 {
		room -= n
	}
	m := len(it.events)
	if room >= 0 && m > room {
		m = room
	}
	for _, e := range it.events[:m] {
		e.ClientHandle = it.clientHandle
		events = append(events, e)
	}
	it.events = it.events[m:]
	return changes, events, len(it.queue) > 0 || len(it.events) > 0
}

// detach stops the item receiving values.
func (it *monitoredItem) detach() {
	if it.isEvent() {
		it.sub.srv.eventSinks.remove(it)
		return
	}
	n := it.node
	n.mu.Lock()
	delete(n.items, it)
	n.mu.Unlock()
}

func (it *monitoredItem) setMode(mode ua.MonitoringMode) {
	it.mu.Lock()
	defer it.mu.Unlock()
	it.mode = mode
	if mode == ua.MonitoringModeDisabled {
		it.queue, it.events, it.last = nil, nil, nil
	}
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.2
func (s *Server) createMonitoredItems(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.CreateMonitoredItemsRequest)
	if err := s.checkOperations(len(req.ItemsToCreate)); err != nil {
		return nil, err
	}
	sub := s.subs.get(req.SubscriptionID, r.Session)
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	if req.TimestampsToReturn > ua.TimestampsToReturnNeither {
		return nil, ua.StatusBadTimestampsToReturnInvalid
	}
	who := r.Session.Identity()
	results := make([]*ua.MonitoredItemCreateResult, len(req.ItemsToCreate))
	for i, c := range req.ItemsToCreate {
		results[i] = s.createItem(sub, who, req.TimestampsToReturn, c)
	}
	return &ua.CreateMonitoredItemsResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func (s *Server) createItem(sub *subscription, who *Identity, ttr ua.TimestampsToReturn, c *ua.MonitoredItemCreateRequest) *ua.MonitoredItemCreateResult {
	fail := func(st ua.StatusCode) *ua.MonitoredItemCreateResult {
		return &ua.MonitoredItemCreateResult{StatusCode: st}
	}
	if c == nil || c.ItemToMonitor == nil || c.RequestedParameters == nil {
		return fail(ua.StatusBadMonitoredItemFilterInvalid)
	}
	sub.mu.Lock()
	full := len(sub.items) >= s.cfg.limits.MaxMonitoredItemsPerSubscription
	sub.mu.Unlock()
	if full {
		return fail(ua.StatusBadTooManyMonitoredItems)
	}
	if c.MonitoringMode > ua.MonitoringModeReporting {
		return fail(ua.StatusBadMonitoringModeInvalid)
	}
	rv := c.ItemToMonitor
	n := s.space.Node(rv.NodeID)
	if n == nil {
		return fail(ua.StatusBadNodeIDUnknown)
	}
	if rv.DataEncoding != nil && rv.DataEncoding.Name != "" && rv.DataEncoding.Name != "Default Binary" {
		return fail(ua.StatusBadDataEncodingInvalid)
	}
	if rv.IndexRange != "" {
		if _, _, ok := parseIndexRange(rv.IndexRange); !ok {
			return fail(ua.StatusBadIndexRangeInvalid)
		}
	}

	it := &monitoredItem{
		sub:           sub,
		node:          n,
		who:           who,
		attr:          rv.AttributeID,
		indexRange:    rv.IndexRange,
		ttr:           ttr,
		clientHandle:  c.RequestedParameters.ClientHandle,
		mode:          c.MonitoringMode,
		discardOldest: c.RequestedParameters.DiscardOldest,
	}
	var filterResult *ua.ExtensionObject
	if rv.AttributeID == ua.AttributeIDEventNotifier {
		fr, st := s.setupEventItem(it, n, who, c.RequestedParameters.Filter)
		if st != ua.StatusOK {
			return &ua.MonitoredItemCreateResult{StatusCode: st, FilterResult: fr}
		}
		filterResult = fr
	} else {
		// The attribute must be readable by this user.
		probe := s.readAttribute(who, &ua.ReadValueID{NodeID: n.id, AttributeID: rv.AttributeID}, ua.TimestampsToReturnNeither)
		switch probe.Status {
		case ua.StatusBadAttributeIDInvalid, ua.StatusBadNotReadable, ua.StatusBadUserAccessDenied:
			return fail(probe.Status)
		}
		if st := s.setFilter(it, n, c.RequestedParameters.Filter); st != ua.StatusOK {
			return fail(st)
		}
	}
	s.reviseItem(it, sub, c.RequestedParameters)

	s.subs.mu.Lock()
	s.subs.nextItem++
	it.id = s.subs.nextItem
	s.subs.mu.Unlock()

	// Settle how the item gets values before the subscription can see it.
	if !it.isEvent() {
		n.mu.RLock()
		pushed := rv.AttributeID == ua.AttributeIDValue && n.valueFunc == nil
		n.mu.RUnlock()
		it.mu.Lock()
		it.pushed = pushed
		it.mu.Unlock()
	}

	sub.mu.Lock()
	sub.items[it.id] = it
	sub.mu.Unlock()

	if it.isEvent() {
		s.eventSinks.add(it)
	} else {
		if it.pushed {
			n.mu.Lock()
			if n.items == nil {
				n.items = make(map[*monitoredItem]struct{})
			}
			n.items[it] = struct{}{}
			n.mu.Unlock()
		}
		// The first value goes out at once (OPC 10000-4 §5.12.1.2).
		dv := it.read()
		it.mu.Lock()
		it.nextSample = time.Now().Add(it.sampling)
		it.offerLocked(dv)
		it.mu.Unlock()
	}

	it.mu.Lock()
	defer it.mu.Unlock()
	return &ua.MonitoredItemCreateResult{
		StatusCode:              ua.StatusOK,
		MonitoredItemID:         it.id,
		RevisedSamplingInterval: float64(it.sampling) / float64(time.Millisecond),
		RevisedQueueSize:        uint32(it.queueSize),
		FilterResult:            filterResult,
	}
}

// reviseItem sets the sampling interval and queue size.
func (s *Server) reviseItem(it *monitoredItem, sub *subscription, p *ua.MonitoringParameters) {
	lim := s.cfg.limits
	d := time.Duration(p.SamplingInterval * float64(time.Millisecond))
	if p.SamplingInterval < 0 {
		sub.mu.Lock()
		d = sub.publishingInterval
		sub.mu.Unlock()
	}
	if d < lim.MinSamplingInterval {
		d = lim.MinSamplingInterval
	}
	it.node.mu.RLock()
	if min := time.Duration(it.node.minSampling * float64(time.Millisecond)); d < min {
		d = min
	}
	it.node.mu.RUnlock()

	q := int(p.QueueSize)
	if it.isEvent() {
		if q == 0 {
			q = lim.MaxQueueSize
		}
	} else if q == 0 {
		q = 1
	}
	if q > lim.MaxQueueSize {
		q = lim.MaxQueueSize
	}
	it.mu.Lock()
	it.sampling, it.queueSize = d, q
	if len(it.queue) > q {
		it.queue = it.queue[len(it.queue)-q:]
	}
	it.mu.Unlock()
}

// setFilter checks and applies a DataChangeFilter (OPC 10000-4 §7.22.2).
func (s *Server) setFilter(it *monitoredItem, n *Node, f *ua.ExtensionObject) ua.StatusCode {
	filter, deadband, st := s.checkFilter(it.attr, n, f)
	if st != ua.StatusOK {
		return st
	}
	it.mu.Lock()
	it.filter, it.deadband = filter, deadband
	it.mu.Unlock()
	return ua.StatusOK
}

// checkFilter checks a DataChangeFilter and returns it with the absolute
// deadband it means.
func (s *Server) checkFilter(attr ua.AttributeID, n *Node, f *ua.ExtensionObject) (*ua.DataChangeFilter, float64, ua.StatusCode) {
	if f == nil || f.Value == nil {
		return nil, 0, ua.StatusOK
	}
	dcf, ok := f.Value.(*ua.DataChangeFilter)
	if !ok {
		return nil, 0, ua.StatusBadFilterNotAllowed
	}
	if dcf.Trigger > ua.DataChangeTriggerStatusValueTimestamp || dcf.DeadbandType > uint32(ua.DeadbandTypePercent) {
		return nil, 0, ua.StatusBadMonitoredItemFilterInvalid
	}
	deadband := 0.0
	if dcf.DeadbandType != uint32(ua.DeadbandTypeNone) {
		if attr != ua.AttributeIDValue {
			return nil, 0, ua.StatusBadFilterNotAllowed
		}
		n.mu.RLock()
		dt, eu := n.dataType, n.euRange
		n.mu.RUnlock()
		if t, numeric := s.builtinOf(dt); !numeric && !isNumericType(t) {
			return nil, 0, ua.StatusBadFilterNotAllowed
		}
		if dcf.DeadbandValue < 0 || math.IsNaN(dcf.DeadbandValue) {
			return nil, 0, ua.StatusBadDeadbandFilterInvalid
		}
		deadband = dcf.DeadbandValue
		if dcf.DeadbandType == uint32(ua.DeadbandTypePercent) {
			// Percent deadband needs the variable's EURange (OPC 10000-8 §6.2).
			if eu == nil {
				return nil, 0, ua.StatusBadMonitoredItemFilterUnsupported
			}
			if dcf.DeadbandValue > 100 {
				return nil, 0, ua.StatusBadDeadbandFilterInvalid
			}
			deadband = dcf.DeadbandValue / 100 * math.Abs(eu.High-eu.Low)
		}
	}
	return dcf, deadband, ua.StatusOK
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.3
func (s *Server) modifyMonitoredItems(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.ModifyMonitoredItemsRequest)
	if err := s.checkOperations(len(req.ItemsToModify)); err != nil {
		return nil, err
	}
	sub := s.subs.get(req.SubscriptionID, r.Session)
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	if req.TimestampsToReturn > ua.TimestampsToReturnNeither {
		return nil, ua.StatusBadTimestampsToReturnInvalid
	}
	results := make([]*ua.MonitoredItemModifyResult, len(req.ItemsToModify))
	for i, m := range req.ItemsToModify {
		sub.mu.Lock()
		it := sub.items[m.MonitoredItemID]
		sub.mu.Unlock()
		if it == nil || m.RequestedParameters == nil {
			results[i] = &ua.MonitoredItemModifyResult{StatusCode: ua.StatusBadMonitoredItemIDInvalid}
			continue
		}
		var fr *ua.ExtensionObject
		if it.isEvent() {
			var st ua.StatusCode
			if fr, st = s.setEventFilter(it, m.RequestedParameters.Filter); st != ua.StatusOK {
				results[i] = &ua.MonitoredItemModifyResult{StatusCode: st, FilterResult: fr}
				continue
			}
		} else {
			if st := s.setFilter(it, it.node, m.RequestedParameters.Filter); st != ua.StatusOK {
				results[i] = &ua.MonitoredItemModifyResult{StatusCode: st}
				continue
			}
		}
		it.mu.Lock()
		it.clientHandle = m.RequestedParameters.ClientHandle
		it.discardOldest = m.RequestedParameters.DiscardOldest
		it.ttr = req.TimestampsToReturn
		it.mu.Unlock()
		s.reviseItem(it, sub, m.RequestedParameters)
		it.mu.Lock()
		results[i] = &ua.MonitoredItemModifyResult{
			StatusCode:              ua.StatusOK,
			RevisedSamplingInterval: float64(it.sampling) / float64(time.Millisecond),
			RevisedQueueSize:        uint32(it.queueSize),
			FilterResult:            fr,
		}
		it.mu.Unlock()
	}
	return &ua.ModifyMonitoredItemsResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.4
func (s *Server) setMonitoringMode(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.SetMonitoringModeRequest)
	if err := s.checkOperations(len(req.MonitoredItemIDs)); err != nil {
		return nil, err
	}
	sub := s.subs.get(req.SubscriptionID, r.Session)
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	if req.MonitoringMode > ua.MonitoringModeReporting {
		return nil, ua.StatusBadMonitoringModeInvalid
	}
	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))
	for i, mid := range req.MonitoredItemIDs {
		sub.mu.Lock()
		it := sub.items[mid]
		sub.mu.Unlock()
		if it == nil {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}
		it.mu.Lock()
		wasDisabled := it.mode == ua.MonitoringModeDisabled
		it.mu.Unlock()
		it.setMode(req.MonitoringMode)
		if wasDisabled && req.MonitoringMode != ua.MonitoringModeDisabled {
			it.sendCurrent()
		}
	}
	return &ua.SetMonitoringModeResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.6
func (s *Server) deleteMonitoredItems(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.DeleteMonitoredItemsRequest)
	if err := s.checkOperations(len(req.MonitoredItemIDs)); err != nil {
		return nil, err
	}
	sub := s.subs.get(req.SubscriptionID, r.Session)
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))
	for i, mid := range req.MonitoredItemIDs {
		sub.mu.Lock()
		it := sub.items[mid]
		delete(sub.items, mid)
		sub.mu.Unlock()
		if it == nil {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}
		it.detach()
	}
	return &ua.DeleteMonitoredItemsResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

// nodeRemoved tells the items of a removed node that it is gone
// (OPC 10000-4 §5.12.1.1) and detaches them.
func nodeRemoved(n *Node) {
	n.mu.Lock()
	items := make([]*monitoredItem, 0, len(n.items))
	for it := range n.items {
		items = append(items, it)
	}
	n.items = nil
	n.mu.Unlock()
	for _, it := range items {
		it.mu.Lock()
		it.offerLocked(&ua.DataValue{Status: ua.StatusBadNodeIDUnknown, ServerTimestamp: time.Now()})
		it.mu.Unlock()
	}
}

var _ = context.Background
