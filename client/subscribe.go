package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ka1hung/opcua"
	"github.com/ka1hung/opcua/ua"
)

// Subscription delivers value changes of nodes.
type Subscription struct {
	sub    *opcua.Subscription
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
func (c *Client) SubscribeWith(ctx context.Context, ids []string, o SubscribeOptions, f func(nodeID string, r Result)) (*Subscription, []Result, error) {
	ch := make(chan *opcua.PublishNotificationData, 256)
	sctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	sub, err := c.c.Subscribe(sctx, &opcua.SubscriptionParameters{Interval: o.Interval}, ch)
	if err != nil {
		return nil, nil, fmt.Errorf("client: subscribe: %w", err)
	}

	results := make([]Result, len(ids))
	var reqs []*ua.MonitoredItemCreateRequest
	var idx []int
	for i, s := range ids {
		results[i].NodeID = s
		nid, err := parse(s)
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
		reqs = append(reqs, req)
		idx = append(idx, i)
	}
	if len(reqs) > 0 {
		resp, err := sub.Monitor(sctx, ua.TimestampsToReturnBoth, reqs...)
		if err != nil {
			_ = sub.Cancel(context.Background())
			return nil, nil, fmt.Errorf("client: monitor: %w", err)
		}
		for k, r := range resp.Results {
			if k < len(idx) {
				results[idx[k]].Status = r.StatusCode
			}
		}
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	s := &Subscription{sub: sub, cancel: runCancel, done: make(chan struct{}), c: c}
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

// Close ends the subscription.
func (s *Subscription) Close() error {
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
