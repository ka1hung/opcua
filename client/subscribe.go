package client

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/ua"
)

// Subscription delivers value changes of nodes.
type Subscription struct {
	subs   []*opcua.Subscription
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	c      *Client
}

// Trigger says which changes a subscription reports (OPC 10000-4 §7.22.2).
type Trigger int

const (
	// TriggerStatusValue reports changes of the status or the value. It is
	// the zero value and the default.
	TriggerStatusValue Trigger = iota
	// TriggerStatus reports changes of the status only.
	TriggerStatus
	// TriggerStatusValueTimestamp also reports a new source timestamp with
	// an unchanged value.
	TriggerStatusValueTimestamp
)

func (t Trigger) ua() ua.DataChangeTrigger {
	switch t {
	case TriggerStatus:
		return ua.DataChangeTriggerStatus
	case TriggerStatusValueTimestamp:
		return ua.DataChangeTriggerStatusValueTimestamp
	}
	return ua.DataChangeTriggerStatusValue
}

// SubscribeOptions tune a subscription. The zero value reports every
// change of status or value.
type SubscribeOptions struct {
	// Interval is how often the server sends changes.
	Interval time.Duration
	// Sampling is how often the server samples each node; 0 uses the
	// node's fastest rate.
	Sampling time.Duration
	// QueueSize is how many changes per node the server keeps between two
	// sends; 0 keeps 10. When it is full the oldest is dropped, or the
	// newest with DiscardNewest.
	QueueSize     uint32
	DiscardNewest bool
	Trigger       Trigger
	// AbsoluteDeadband ignores changes smaller than this. PercentDeadband
	// ignores changes smaller than this percent of the node's EURange; the
	// node must have one. Set at most one.
	AbsoluteDeadband float64
	PercentDeadband  float64
}

func (o SubscribeOptions) filter() *ua.ExtensionObject {
	if o.Trigger == TriggerStatusValue && o.AbsoluteDeadband == 0 && o.PercentDeadband == 0 {
		return nil
	}
	f := &ua.DataChangeFilter{Trigger: o.Trigger.ua()}
	switch {
	case o.AbsoluteDeadband > 0:
		f.DeadbandType, f.DeadbandValue = uint32(ua.DeadbandTypeAbsolute), o.AbsoluteDeadband
	case o.PercentDeadband > 0:
		f.DeadbandType, f.DeadbandValue = uint32(ua.DeadbandTypePercent), o.PercentDeadband
	}
	return ua.NewExtensionObject(f)
}

// Subscribe reports value changes of the nodes to f, from one goroutine,
// starting with each node's current value. It returns the result for
// each node: a malformed or unknown node id fails only that node.
func (c *Client) Subscribe(ctx context.Context, ids []string, interval time.Duration, f func(nodeID string, r Result)) (*Subscription, []Result, error) {
	return c.SubscribeWith(ctx, ids, SubscribeOptions{Interval: interval}, f)
}

// SubscribeWith is Subscribe with options: deadband, queue size, sampling
// and trigger. A node whose options the server refuses, such as a percent
// deadband without EURange, fails with its own Bad status.
//
// Any number of nodes can be subscribed: the items are created in calls of
// at most the server's MaxMonitoredItemsPerCall, and when a subscription is
// full (Bad_TooManyMonitoredItems) the rest go to another subscription.
// Nodes that no subscription accepts keep that Bad status.
func (c *Client) SubscribeWith(ctx context.Context, ids []string, o SubscribeOptions, f func(nodeID string, r Result)) (*Subscription, []Result, error) {
	ch := make(chan *opcua.PublishNotificationData, 256)
	s := &Subscription{c: c, done: make(chan struct{})}
	newSub := func() (*opcua.Subscription, error) {
		sctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		sub, err := c.c.Subscribe(sctx, &opcua.SubscriptionParameters{Interval: o.Interval}, ch)
		if err != nil {
			return nil, err
		}
		s.subs = append(s.subs, sub)
		return sub, nil
	}
	if _, err := newSub(); err != nil {
		return nil, nil, fmt.Errorf("client: subscribe: %w", err)
	}

	results := make([]Result, len(ids))
	var pending []int // indexes into ids still to monitor
	reqOf := map[int]*ua.MonitoredItemCreateRequest{}
	for i, str := range ids {
		results[i].NodeID = str
		nid, err := c.parse(str)
		if err != nil {
			results[i].Err, results[i].Status = err, ua.StatusBadNodeIDInvalid
			continue
		}
		req := opcua.NewMonitoredItemCreateRequestWithDefaults(nid, ua.AttributeIDValue, uint32(i))
		p := req.RequestedParameters
		p.SamplingInterval = float64(o.Sampling) / float64(time.Millisecond)
		if o.QueueSize > 0 {
			p.QueueSize = o.QueueSize
		}
		p.DiscardOldest = !o.DiscardNewest
		p.Filter = o.filter()
		reqOf[i] = req
		pending = append(pending, i)
	}

	c.mu.Lock()
	per := c.maxMonitor
	c.mu.Unlock()
	if per <= 0 {
		per = 1000
	}
	const maxSubs = 64
	for len(pending) > 0 {
		sub := s.subs[len(s.subs)-1]
		var full []int // refused because this subscription is full
		accepted := 0
		for len(pending) > 0 {
			n := min(per, len(pending))
			chunk := pending[:n]
			reqs := make([]*ua.MonitoredItemCreateRequest, n)
			for k, i := range chunk {
				reqs[k] = reqOf[i]
			}
			mctx, cancel := context.WithTimeout(ctx, c.timeout)
			resp, err := sub.Monitor(mctx, ua.TimestampsToReturnBoth, reqs...)
			cancel()
			if errors.Is(err, ua.StatusBadTooManyOperations) && per > 1 {
				per /= 2 // the server allows fewer items per call than it said
				continue
			}
			if err != nil {
				s.cancelAll()
				return nil, nil, fmt.Errorf("client: monitor: %w", err)
			}
			for k, r := range resp.Results {
				if k >= len(chunk) {
					break
				}
				i := chunk[k]
				results[i].Status = r.StatusCode
				switch {
				case r.StatusCode == ua.StatusBadTooManyMonitoredItems:
					full = append(full, i)
				case r.StatusCode == ua.StatusOK || uint32(r.StatusCode)&0x80000000 == 0:
					accepted++
				}
			}
			pending = pending[n:]
		}
		if len(full) == 0 {
			break
		}
		if accepted == 0 && len(s.subs) > 1 || len(s.subs) >= maxSubs {
			break // a new subscription takes nothing more: leave them Bad_TooManyMonitoredItems
		}
		if _, err := newSub(); err != nil {
			break // e.g. Bad_TooManySubscriptions: the rest keep their status
		}
		pending = full
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	s.cancel = runCancel
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
				dc, ok := n.Value.(*ua.DataChangeNotification)
				if !ok {
					continue
				}
				for _, item := range dc.MonitoredItems {
					h := int(item.ClientHandle)
					if h >= len(ids) || item.Value == nil {
						continue
					}
					r := Result{NodeID: ids[h], Status: item.Value.Status, SourceTime: item.Value.SourceTimestamp, ServerTime: item.Value.ServerTimestamp}
					if item.Value.Value != nil {
						r.Value = item.Value.Value.Value()
					}
					f(ids[h], r)
				}
			}
		}
	}()
	return s, results, nil
}

// Count returns how many server subscriptions carry the nodes.
func (s *Subscription) Count() int { return len(s.subs) }

func (s *Subscription) cancelAll() {
	for _, sub := range s.subs {
		ctx, cancel := context.WithTimeout(context.Background(), s.c.timeout)
		_ = sub.Cancel(ctx)
		cancel()
	}
}

// Close ends the subscription.
func (s *Subscription) Close() error {
	var err error
	s.once.Do(func() {
		s.cancel()
		<-s.done
		for _, sub := range s.subs {
			ctx, cancel := context.WithTimeout(context.Background(), s.c.timeout)
			if e := sub.Cancel(ctx); e != nil && err == nil {
				err = e
			}
			cancel()
		}
	})
	return err
}
