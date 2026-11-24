package server

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uasc"
)

// pubReq is a queued Publish request (OPC 10000-4 §5.13.5).
type pubReq struct {
	sc       *uasc.SecureChannel
	reqID    uint32
	req      *ua.PublishRequest
	results  []ua.StatusCode // of the acknowledgements it carried
	received time.Time
}

// publishQueue holds a session's Publish requests until a subscription
// has something to send.
type publishQueue struct {
	mu  sync.Mutex
	max int
	q   []*pubReq
}

func (p *publishQueue) init(max int) { p.max = max }

// add queues r. When the queue is full the oldest request is answered with
// Bad_TooManyPublishRequests (OPC 10000-4 §5.13.5).
func (p *publishQueue) add(r *pubReq) {
	p.mu.Lock()
	var dropped *pubReq
	if len(p.q) >= p.max {
		dropped, p.q = p.q[0], p.q[1:]
	}
	p.q = append(p.q, r)
	p.mu.Unlock()
	if dropped != nil {
		dropped.fault(ua.StatusBadTooManyPublishRequests)
	}
}

func (p *publishQueue) take() *pubReq {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.q) == 0 {
		return nil
	}
	r := p.q[0]
	p.q = p.q[1:]
	return r
}

func (p *publishQueue) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.q)
}

// expire answers requests that waited longer than their TimeoutHint.
func (p *publishQueue) expire(now time.Time) {
	p.mu.Lock()
	var gone []*pubReq
	keep := p.q[:0]
	for _, r := range p.q {
		hint := time.Duration(0)
		if h := r.req.RequestHeader; h != nil {
			hint = time.Duration(h.TimeoutHint) * time.Millisecond
		}
		if hint > 0 && now.Sub(r.received) > hint {
			gone = append(gone, r)
		} else {
			keep = append(keep, r)
		}
	}
	p.q = keep
	p.mu.Unlock()
	for _, r := range gone {
		r.fault(ua.StatusBadTimeout)
	}
}

func (p *publishQueue) closeAll(status ua.StatusCode) {
	p.mu.Lock()
	q := p.q
	p.q = nil
	p.mu.Unlock()
	for _, r := range q {
		r.fault(status)
	}
}

func (r *pubReq) handle() uint32 {
	if r.req.RequestHeader == nil {
		return 0
	}
	return r.req.RequestHeader.RequestHandle
}

func (r *pubReq) fault(status ua.StatusCode) {
	_ = r.sc.SendResponseWithContext(context.Background(), r.reqID,
		&ua.ServiceFault{ResponseHeader: responseHeader(r.handle(), status)})
}

func (r *pubReq) send(resp *ua.PublishResponse) {
	resp.ResponseHeader = responseHeader(r.handle(), ua.StatusOK)
	resp.Results = r.results
	_ = r.sc.SendResponseWithContext(context.Background(), r.reqID, resp)
}

type subscriptionManager struct {
	srv *Server

	mu       sync.Mutex
	subs     map[uint32]*subscription
	nextSub  uint32
	nextItem uint32
}

func newSubscriptionManager(srv *Server) *subscriptionManager {
	return &subscriptionManager{srv: srv, subs: make(map[uint32]*subscription)}
}

func (m *subscriptionManager) get(id uint32, sess *Session) *subscription {
	m.mu.Lock()
	defer m.mu.Unlock()
	sub := m.subs[id]
	if sub == nil || sub.owner() != sess {
		return nil
	}
	return sub
}

func (m *subscriptionManager) ofSession(sess *Session) []*subscription {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*subscription
	for _, sub := range m.subs {
		if sub.owner() == sess {
			out = append(out, sub)
		}
	}
	return out
}

func (m *subscriptionManager) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.subs)
}

func (m *subscriptionManager) remove(sub *subscription) {
	m.mu.Lock()
	delete(m.subs, sub.id)
	m.mu.Unlock()
	sub.stop()
}

func (m *subscriptionManager) deleteSession(sess *Session) {
	for _, sub := range m.ofSession(sess) {
		m.remove(sub)
	}
}

// orphan detaches the subscriptions of a closed session; they live on
// until their lifetime ends or another session transfers them.
func (m *subscriptionManager) orphan(sess *Session) {
	for _, sub := range m.ofSession(sess) {
		sub.mu.Lock()
		sub.session = nil
		sub.mu.Unlock()
	}
}

func (m *subscriptionManager) sessionChannelChanged(sess *Session) {}

func (m *subscriptionManager) stop() {
	m.mu.Lock()
	subs := make([]*subscription, 0, len(m.subs))
	for _, sub := range m.subs {
		subs = append(subs, sub)
	}
	m.subs = make(map[uint32]*subscription)
	m.mu.Unlock()
	for _, sub := range subs {
		sub.stop()
	}
}

// subscription is one Subscription (OPC 10000-4 §5.13.1).
type subscription struct {
	srv *Server
	id  uint32

	mu                 sync.Mutex
	session            *Session
	publishingInterval time.Duration
	maxKeepAlive       uint32
	lifetime           uint32
	maxNotifications   uint32
	priority           uint8
	enabled            bool
	items              map[uint32]*monitoredItem

	seq            uint32 // last sequence number sent
	keepAliveCount uint32
	lifetimeCount  uint32
	late           bool
	retrans        []*ua.NotificationMessage
	pendingStatus  []ua.StatusCode

	reset    chan time.Duration
	poke     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

func (sub *subscription) owner() *Session {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.session
}

// revise applies the parameter rules of OPC 10000-4 §5.13.2.
func (s *Server) revise(interval float64, lifetime, keepAlive uint32) (time.Duration, uint32, uint32) {
	lim := s.cfg.limits
	d := time.Duration(interval * float64(time.Millisecond))
	if math.IsNaN(interval) || d < lim.MinPublishingInterval {
		d = lim.MinPublishingInterval
	}
	if d > time.Hour {
		d = time.Hour
	}
	if keepAlive == 0 {
		keepAlive = 10
	}
	// A keep-alive at least every 10 minutes.
	if maxKA := uint32(10 * time.Minute / d); maxKA > 0 && keepAlive > maxKA {
		keepAlive = maxKA
	}
	if lifetime < 3*keepAlive {
		lifetime = 3 * keepAlive
	}
	// A subscription lives at most an hour without Publish requests.
	if maxLT := uint32(time.Hour / d); maxLT >= 3*keepAlive && lifetime > maxLT {
		lifetime = maxLT
	}
	return d, lifetime, keepAlive
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.2
func (s *Server) createSubscription(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.CreateSubscriptionRequest)
	if len(s.subs.ofSession(r.Session)) >= s.cfg.limits.MaxSubscriptionsPerSession {
		return nil, ua.StatusBadTooManySubscriptions
	}
	d, lt, ka := s.revise(req.RequestedPublishingInterval, req.RequestedLifetimeCount, req.RequestedMaxKeepAliveCount)

	m := s.subs
	m.mu.Lock()
	m.nextSub++
	for m.nextSub == 0 || m.subs[m.nextSub] != nil {
		m.nextSub++
	}
	sub := &subscription{
		srv:                s,
		id:                 m.nextSub,
		session:            r.Session,
		publishingInterval: d,
		maxKeepAlive:       ka,
		lifetime:           lt,
		maxNotifications:   req.MaxNotificationsPerPublish,
		priority:           req.Priority,
		enabled:            req.PublishingEnabled,
		items:              make(map[uint32]*monitoredItem),
		// The first publishing cycle sends a keep-alive if there is no
		// data, so the client learns the subscription works.
		keepAliveCount: ka,
		reset:          make(chan time.Duration, 1),
		poke:           make(chan struct{}, 1),
		done:           make(chan struct{}),
	}
	m.subs[sub.id] = sub
	m.mu.Unlock()
	go sub.run()

	return &ua.CreateSubscriptionResponse{
		ResponseHeader:            okHeader(req),
		SubscriptionID:            sub.id,
		RevisedPublishingInterval: float64(d) / float64(time.Millisecond),
		RevisedLifetimeCount:      lt,
		RevisedMaxKeepAliveCount:  ka,
	}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.3
func (s *Server) modifySubscription(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.ModifySubscriptionRequest)
	sub := s.subs.get(req.SubscriptionID, r.Session)
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	d, lt, ka := s.revise(req.RequestedPublishingInterval, req.RequestedLifetimeCount, req.RequestedMaxKeepAliveCount)
	sub.mu.Lock()
	changed := sub.publishingInterval != d
	sub.publishingInterval, sub.lifetime, sub.maxKeepAlive = d, lt, ka
	sub.maxNotifications, sub.priority = req.MaxNotificationsPerPublish, req.Priority
	sub.lifetimeCount = 0
	sub.mu.Unlock()
	if changed {
		select {
		case sub.reset <- d:
		default:
		}
	}
	return &ua.ModifySubscriptionResponse{
		ResponseHeader:            okHeader(req),
		RevisedPublishingInterval: float64(d) / float64(time.Millisecond),
		RevisedLifetimeCount:      lt,
		RevisedMaxKeepAliveCount:  ka,
	}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.4
func (s *Server) setPublishingMode(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.SetPublishingModeRequest)
	if err := s.checkOperations(len(req.SubscriptionIDs)); err != nil {
		return nil, err
	}
	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	for i, sid := range req.SubscriptionIDs {
		sub := s.subs.get(sid, r.Session)
		if sub == nil {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		sub.mu.Lock()
		sub.enabled = req.PublishingEnabled
		sub.lifetimeCount = 0
		sub.mu.Unlock()
	}
	return &ua.SetPublishingModeResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.5
func (s *Server) publish(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.PublishRequest)
	sess := r.Session
	results := make([]ua.StatusCode, len(req.SubscriptionAcknowledgements))
	for i, ack := range req.SubscriptionAcknowledgements {
		sub := s.subs.get(ack.SubscriptionID, sess)
		if sub == nil {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		results[i] = sub.acknowledge(ack.SequenceNumber)
	}
	subs := s.subs.ofSession(sess)
	if len(subs) == 0 {
		return nil, ua.StatusBadNoSubscription
	}
	sess.pub.add(&pubReq{sc: r.SC, reqID: r.ID, req: req, results: results, received: time.Now()})

	// A late subscription is served at once, highest priority first.
	sort.Slice(subs, func(i, j int) bool { return subs[i].priority > subs[j].priority })
	for _, sub := range subs {
		sub.mu.Lock()
		late := sub.late
		sub.mu.Unlock()
		if late {
			select {
			case sub.poke <- struct{}{}:
			default:
			}
			break
		}
	}
	return nil, nil
}

func (sub *subscription) acknowledge(seq uint32) ua.StatusCode {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	for i, m := range sub.retrans {
		if m.SequenceNumber == seq {
			sub.retrans = append(sub.retrans[:i], sub.retrans[i+1:]...)
			return ua.StatusOK
		}
	}
	return ua.StatusBadSequenceNumberUnknown
}

func (sub *subscription) available() []uint32 {
	out := make([]uint32, len(sub.retrans))
	for i, m := range sub.retrans {
		out[i] = m.SequenceNumber
	}
	return out
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.6
func (s *Server) republish(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.RepublishRequest)
	sub := s.subs.get(req.SubscriptionID, r.Session)
	if sub == nil {
		return nil, ua.StatusBadSubscriptionIDInvalid
	}
	sub.mu.Lock()
	defer sub.mu.Unlock()
	for _, m := range sub.retrans {
		if m.SequenceNumber == req.RetransmitSequenceNumber {
			return &ua.RepublishResponse{ResponseHeader: okHeader(req), NotificationMessage: m}, nil
		}
	}
	return nil, ua.StatusBadMessageNotAvailable
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.7
func (s *Server) transferSubscriptions(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.TransferSubscriptionsRequest)
	if err := s.checkOperations(len(req.SubscriptionIDs)); err != nil {
		return nil, err
	}
	who := r.Session.Identity()
	results := make([]*ua.TransferResult, len(req.SubscriptionIDs))
	for i, sid := range req.SubscriptionIDs {
		s.subs.mu.Lock()
		sub := s.subs.subs[sid]
		s.subs.mu.Unlock()
		if sub == nil {
			results[i] = &ua.TransferResult{StatusCode: ua.StatusBadSubscriptionIDInvalid}
			continue
		}
		sub.mu.Lock()
		old := sub.session
		var oldWho *Identity
		if old != nil {
			oldWho = old.Identity()
		} else {
			oldWho = sub.lastOwner()
		}
		if !who.sameUser(oldWho) {
			sub.mu.Unlock()
			results[i] = &ua.TransferResult{StatusCode: ua.StatusBadUserAccessDenied}
			continue
		}
		sub.session = r.Session
		sub.lifetimeCount = 0
		avail := sub.available()
		items := make([]*monitoredItem, 0, len(sub.items))
		for _, it := range sub.items {
			items = append(items, it)
		}
		sub.mu.Unlock()
		if old != nil && old != r.Session {
			// The old session learns that it lost the subscription.
			old.pub.closeAllFor(sub, ua.StatusGoodSubscriptionTransferred)
		}
		if req.SendInitialValues {
			for _, it := range items {
				it.sendCurrent()
			}
		}
		results[i] = &ua.TransferResult{StatusCode: ua.StatusOK, AvailableSequenceNumbers: avail}
	}
	return &ua.TransferSubscriptionsResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

// lastOwner is the identity of an orphaned subscription's last session.
// Called with sub.mu held.
func (sub *subscription) lastOwner() *Identity {
	for _, it := range sub.items {
		return it.who
	}
	return anonymous
}

// closeAllFor sends a StatusChangeNotification for sub with one queued
// Publish request of the session, if there is one.
func (p *publishQueue) closeAllFor(sub *subscription, status ua.StatusCode) {
	r := p.take()
	if r == nil {
		return
	}
	r.send(&ua.PublishResponse{
		SubscriptionID: sub.id,
		NotificationMessage: &ua.NotificationMessage{
			PublishTime:      time.Now(),
			NotificationData: []*ua.ExtensionObject{ua.NewExtensionObject(&ua.StatusChangeNotification{Status: status, DiagnosticInfo: &ua.DiagnosticInfo{}})},
		},
	})
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.8
func (s *Server) deleteSubscriptions(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.DeleteSubscriptionsRequest)
	if err := s.checkOperations(len(req.SubscriptionIDs)); err != nil {
		return nil, err
	}
	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	for i, sid := range req.SubscriptionIDs {
		sub := s.subs.get(sid, r.Session)
		if sub == nil {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		s.subs.remove(sub)
	}
	// Publish requests are answered while subscriptions remain; with none
	// left, queued requests get Bad_NoSubscription.
	if len(s.subs.ofSession(r.Session)) == 0 {
		r.Session.pub.closeAll(ua.StatusBadNoSubscription)
	}
	return &ua.DeleteSubscriptionsResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func (sub *subscription) stop() {
	sub.stopOnce.Do(func() {
		close(sub.done)
		sub.mu.Lock()
		items := sub.items
		sub.items = map[uint32]*monitoredItem{}
		sub.mu.Unlock()
		for _, it := range items {
			it.detach()
		}
	})
}

// run is the publishing timer of the subscription.
func (sub *subscription) run() {
	sub.mu.Lock()
	d := sub.publishingInterval
	sub.mu.Unlock()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-sub.done:
			return
		case d := <-sub.reset:
			t.Reset(d)
		case <-sub.poke:
			sub.cycle(true)
		case <-t.C:
			sub.cycle(false)
		}
	}
}

// cycle is one publishing cycle (OPC 10000-4 §5.13.1.2). poked is set when
// a Publish request arrived for a late subscription.
func (sub *subscription) cycle(poked bool) {
	sub.mu.Lock()
	sess := sub.session
	if sess == nil {
		sub.lifetimeCount++
		expired := sub.lifetimeCount >= sub.lifetime
		sub.mu.Unlock()
		if expired {
			sub.srv.subs.remove(sub)
		}
		return
	}
	if !poked {
		sub.sampleLocked()
	}
	hasData := sub.enabled && sub.hasDataLocked()
	keepAliveDue := sub.keepAliveCount+1 >= sub.maxKeepAlive
	if !hasData && !keepAliveDue && len(sub.pendingStatus) == 0 {
		if !poked {
			sub.keepAliveCount++
			if sess.pub.len() == 0 {
				sub.lifetimeCount++
			} else {
				sub.lifetimeCount = 0
			}
		}
		expired := sub.lifetimeCount >= sub.lifetime
		sub.mu.Unlock()
		if expired {
			sub.expire()
		}
		return
	}

	req := sess.pub.take()
	if req == nil {
		sub.late = true
		if !poked {
			sub.lifetimeCount++
		}
		expired := sub.lifetimeCount >= sub.lifetime
		sub.mu.Unlock()
		if expired {
			sub.expire()
		}
		return
	}
	sub.late = false
	sub.lifetimeCount = 0
	sub.keepAliveCount = 0

	resp := &ua.PublishResponse{SubscriptionID: sub.id}
	msg := &ua.NotificationMessage{PublishTime: time.Now()}
	if hasData || len(sub.pendingStatus) > 0 {
		var more bool
		msg.NotificationData, more = sub.collectLocked()
		for _, st := range sub.pendingStatus {
			msg.NotificationData = append(msg.NotificationData,
				ua.NewExtensionObject(&ua.StatusChangeNotification{Status: st, DiagnosticInfo: &ua.DiagnosticInfo{}}))
		}
		sub.pendingStatus = nil
		if len(msg.NotificationData) > 0 {
			sub.seq = nextSeq(sub.seq)
			msg.SequenceNumber = sub.seq
			sub.retrans = append(sub.retrans, msg)
			if max := sub.srv.cfg.limits.MaxRetransmissionQueue; len(sub.retrans) > max {
				sub.retrans = sub.retrans[len(sub.retrans)-max:]
			}
		} else {
			msg.SequenceNumber = nextSeq(sub.seq)
		}
		resp.MoreNotifications = more
		if more {
			// Send the rest as soon as another Publish request arrives.
			sub.late = true
		}
	} else {
		// Keep-alive: the next sequence number, which is not consumed.
		msg.SequenceNumber = nextSeq(sub.seq)
	}
	resp.NotificationMessage = msg
	resp.AvailableSequenceNumbers = sub.available()
	sub.mu.Unlock()
	req.send(resp)
}

// nextSeq returns the sequence number after seq; 0 is skipped on wrap
// (OPC 10000-4 §7.38).
func nextSeq(seq uint32) uint32 {
	seq++
	if seq == 0 {
		seq = 1
	}
	return seq
}

// expire ends a subscription whose lifetime ran out (OPC 10000-4 §5.13.1.1).
// The client learns it from a StatusChangeNotification if a Publish
// request is queued.
func (sub *subscription) expire() {
	if sess := sub.owner(); sess != nil {
		sess.pub.closeAllFor(sub, ua.StatusBadTimeout)
	}
	sub.srv.logInfo("subscription %d expired", sub.id)
	sub.srv.subs.remove(sub)
}

func (sub *subscription) sampleLocked() {
	now := time.Now()
	for _, it := range sub.items {
		it.sample(now)
	}
}

func (sub *subscription) hasDataLocked() bool {
	for _, it := range sub.items {
		if it.hasData() {
			return true
		}
	}
	return false
}

// collectLocked drains the queues of reporting items, at most
// maxNotifications values; more reports that some were left.
func (sub *subscription) collectLocked() (data []*ua.ExtensionObject, more bool) {
	limit := int(sub.maxNotifications)
	ids := make([]uint32, 0, len(sub.items))
	for id := range sub.items {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var changes []*ua.MonitoredItemNotification
	var events []*ua.EventFieldList
	for _, id := range ids {
		it := sub.items[id]
		room := -1
		if limit > 0 {
			room = limit - len(changes) - len(events)
			if room <= 0 {
				more = more || it.hasData()
				continue
			}
		}
		c, e, left := it.drain(room)
		changes = append(changes, c...)
		events = append(events, e...)
		more = more || left
	}
	if len(changes) > 0 {
		data = append(data, ua.NewExtensionObject(&ua.DataChangeNotification{MonitoredItems: changes, DiagnosticInfos: []*ua.DiagnosticInfo{}}))
	}
	if len(events) > 0 {
		data = append(data, ua.NewExtensionObject(&ua.EventNotificationList{Events: events}))
	}
	return data, more
}
