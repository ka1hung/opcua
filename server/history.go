package server

import (
	"context"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// HistoryReader supplies stored history; the server does the protocol:
// checks, paging with continuation points, timestamps and event filters
// (OPC 10000-11).
//
// cont is the position where the previous call for the same request
// stopped, nil at first. A reader returns at most max items (max > 0)
// and, if there are more, a non-nil next position. Values come in time
// order: ascending, or descending when start is after end.
type HistoryReader interface {
	// ReadRaw returns the stored values of a variable between start and
	// end. A zero start or end is open. With bounds, the values just
	// outside the range are included when they exist.
	ReadRaw(ctx context.Context, node *ua.NodeID, start, end time.Time, max int, bounds bool, cont []byte) (values []*ua.DataValue, next []byte, err error)
	// ReadAtTime returns, for each time, the value that was current then:
	// the last stored value at or before it, or a value with status
	// Bad_NoData.
	ReadAtTime(ctx context.Context, node *ua.NodeID, times []time.Time) ([]*ua.DataValue, error)
	// ReadEvents returns the stored events of a notifier between start
	// and end.
	ReadEvents(ctx context.Context, notifier *ua.NodeID, start, end time.Time, max int, cont []byte) (events []*Event, next []byte, err error)
}

// maxHistoryValues caps the values returned per node and call; the rest
// come with a continuation point.
const maxHistoryValues = 10000

// SetHistory sets the source of history. Variables with Historizing and
// notifiers with history are read from it.
func (s *Server) SetHistory(h HistoryReader) {
	s.writeMu.Lock()
	s.history = h
	s.writeMu.Unlock()
	// The Server object reports all events, so its event history is the
	// reader's as well.
	if n := s.space.Node(ua.NewNumericNodeID(0, id.Server)); n != nil {
		n.mu.Lock()
		if h != nil {
			n.eventNotifier |= EventNotifierHistoryRead
		} else {
			n.eventNotifier &^= EventNotifierHistoryRead
		}
		n.mu.Unlock()
	}
}

func (s *Server) historyReader() HistoryReader {
	s.writeMu.RLock()
	defer s.writeMu.RUnlock()
	return s.history
}

// historyCP is a continuation point of a HistoryRead.
type historyCP struct {
	node *ua.NodeID
	pos  []byte
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.10.3
func (s *Server) historyRead(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.HistoryReadRequest)
	if err := s.checkOperations(len(req.NodesToRead)); err != nil {
		return nil, err
	}
	if req.TimestampsToReturn > ua.TimestampsToReturnNeither {
		return nil, ua.StatusBadTimestampsToReturnInvalid
	}
	if req.HistoryReadDetails == nil || req.HistoryReadDetails.Value == nil {
		return nil, ua.StatusBadHistoryOperationInvalid
	}
	sess := r.Session
	results := make([]*ua.HistoryReadResult, len(req.NodesToRead))

	if req.ReleaseContinuationPoints {
		for i, n := range req.NodesToRead {
			sess.mu.Lock()
			delete(sess.historyCPs, string(n.ContinuationPoint))
			sess.mu.Unlock()
			results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusOK}
		}
		return &ua.HistoryReadResponse{ResponseHeader: okHeader(req), Results: results}, nil
	}

	h := s.historyReader()
	who := sess.Identity()
	for i, n := range req.NodesToRead {
		if h == nil {
			results[i] = &ua.HistoryReadResult{StatusCode: ua.StatusBadHistoryOperationUnsupported}
			continue
		}
		results[i] = s.historyReadNode(ctx, h, sess, who, req, i, n)
	}
	return &ua.HistoryReadResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func (s *Server) historyReadNode(ctx context.Context, h HistoryReader, sess *Session, who *Identity, req *ua.HistoryReadRequest, idx int, rv *ua.HistoryReadValueID) *ua.HistoryReadResult {
	fail := func(st ua.StatusCode) *ua.HistoryReadResult { return &ua.HistoryReadResult{StatusCode: st} }
	if rv == nil || rv.NodeID == nil {
		return fail(ua.StatusBadNodeIDInvalid)
	}
	n := s.space.Node(rv.NodeID)
	if n == nil {
		return fail(ua.StatusBadNodeIDUnknown)
	}
	if rv.DataEncoding != nil && rv.DataEncoding.Name != "" && rv.DataEncoding.Name != "Default Binary" {
		return fail(ua.StatusBadDataEncodingInvalid)
	}

	// Continue where the last call stopped.
	var pos []byte
	if len(rv.ContinuationPoint) > 0 {
		sess.mu.Lock()
		cp, ok := sess.historyCPs[string(rv.ContinuationPoint)]
		delete(sess.historyCPs, string(rv.ContinuationPoint))
		sess.mu.Unlock()
		if !ok || !sameID(cp.node, rv.NodeID) {
			return fail(ua.StatusBadContinuationPointInvalid)
		}
		pos = cp.pos
	}

	switch d := req.HistoryReadDetails.Value.(type) {
	case *ua.ReadRawModifiedDetails:
		if st := s.checkHistoryVariable(n, who); st != ua.StatusOK {
			return fail(st)
		}
		if d.IsReadModified {
			return fail(ua.StatusBadHistoryOperationUnsupported)
		}
		if d.StartTime.IsZero() && d.EndTime.IsZero() || d.NumValuesPerNode == 0 && (d.StartTime.IsZero() || d.EndTime.IsZero()) {
			return fail(ua.StatusBadInvalidTimestampArgument)
		}
		max := int(d.NumValuesPerNode)
		if max == 0 || max > maxHistoryValues {
			max = maxHistoryValues
		}
		vals, next, err := h.ReadRaw(ctx, n.id, d.StartTime, d.EndTime, max, d.ReturnBounds, pos)
		if err != nil {
			return fail(historyError(err))
		}
		for i, v := range vals {
			vals[i] = withTimestamps(v, req.TimestampsToReturn)
		}
		res := &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: vals})}
		if len(vals) == 0 && next == nil {
			res.StatusCode = ua.StatusGoodNoData
		}
		return s.withContinuation(sess, n.id, next, res)

	case *ua.ReadAtTimeDetails:
		if st := s.checkHistoryVariable(n, who); st != ua.StatusOK {
			return fail(st)
		}
		if len(d.ReqTimes) == 0 {
			return fail(ua.StatusBadInvalidTimestampArgument)
		}
		vals, err := h.ReadAtTime(ctx, n.id, d.ReqTimes)
		if err != nil {
			return fail(historyError(err))
		}
		for i, v := range vals {
			vals[i] = withTimestamps(v, req.TimestampsToReturn)
		}
		return &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: vals})}

	case *ua.ReadEventDetails:
		n.mu.RLock()
		en := n.eventNotifier
		n.mu.RUnlock()
		if n.class != ua.NodeClassObject && n.class != ua.NodeClassView || en&EventNotifierHistoryRead == 0 {
			return fail(ua.StatusBadHistoryOperationUnsupported)
		}
		if d.Filter == nil || len(d.Filter.SelectClauses) == 0 {
			return fail(ua.StatusBadHistoryOperationInvalid)
		}
		if d.StartTime.IsZero() && d.EndTime.IsZero() {
			return fail(ua.StatusBadInvalidTimestampArgument)
		}
		probe := &monitoredItem{}
		if _, st := s.setEventFilter(probe, ua.NewExtensionObject(d.Filter)); st != ua.StatusOK {
			return fail(st)
		}
		max := int(d.NumValuesPerNode)
		if max == 0 || max > maxHistoryValues {
			max = maxHistoryValues
		}
		evs, next, err := h.ReadEvents(ctx, n.id, d.StartTime, d.EndTime, max, pos)
		if err != nil {
			return fail(historyError(err))
		}
		out := make([]*ua.HistoryEventFieldList, 0, len(evs))
		for _, ev := range evs {
			data, err := s.eventData(ev)
			if err != nil {
				continue
			}
			if v, ok := ev.Fields["EventId"]; ok {
				if vv, err := ua.NewVariant(v); err == nil {
					data.fields["EventId"] = vv
				}
			}
			if wc := d.Filter.WhereClause; wc != nil && len(wc.Elements) > 0 && !s.evalFilter(wc, 0, data, 0).truthy() {
				continue
			}
			fields := make([]*ua.Variant, len(d.Filter.SelectClauses))
			for i, sc := range d.Filter.SelectClauses {
				fields[i] = s.selectField(sc, data)
			}
			out = append(out, &ua.HistoryEventFieldList{EventFields: fields})
		}
		res := &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryEvent{Events: out})}
		if len(out) == 0 && next == nil {
			res.StatusCode = ua.StatusGoodNoData
		}
		return s.withContinuation(sess, n.id, next, res)

	case *ua.ReadProcessedDetails:
		// One aggregate per node to read (OPC 10000-11 §6.4.4).
		if len(d.AggregateType) != len(req.NodesToRead) {
			return fail(ua.StatusBadAggregateListMismatch)
		}
		if st := s.checkHistoryVariable(n, who); st != ua.StatusOK {
			return fail(st)
		}
		vals, next, st := s.readProcessed(ctx, h, n, d, d.AggregateType[idx], pos)
		if st != ua.StatusOK {
			return fail(st)
		}
		for i, v := range vals {
			vals[i] = withTimestamps(v, req.TimestampsToReturn)
		}
		res := &ua.HistoryReadResult{StatusCode: ua.StatusOK, HistoryData: ua.NewExtensionObject(&ua.HistoryData{DataValues: vals})}
		return s.withContinuation(sess, n.id, next, res)
	}
	return fail(ua.StatusBadHistoryOperationInvalid)
}

// checkHistoryVariable checks that a variable has history the user may
// read.
func (s *Server) checkHistoryVariable(n *Node, who *Identity) ua.StatusCode {
	if n.class != ua.NodeClassVariable {
		return ua.StatusBadHistoryOperationUnsupported
	}
	n.mu.RLock()
	al, hist := n.accessLevel, n.historizing
	n.mu.RUnlock()
	if !hist && al&AccessLevelHistoryRead == 0 {
		return ua.StatusBadHistoryOperationUnsupported
	}
	if al&AccessLevelHistoryRead == 0 {
		return ua.StatusBadNotReadable
	}
	if s.userAccessLevel(n, who)&AccessLevelHistoryRead == 0 {
		return ua.StatusBadUserAccessDenied
	}
	return ua.StatusOK
}

// withContinuation keeps the reader's position behind a continuation
// point of the session.
func (s *Server) withContinuation(sess *Session, node *ua.NodeID, next []byte, res *ua.HistoryReadResult) *ua.HistoryReadResult {
	if next == nil {
		return res
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.historyCPs) >= s.cfg.limits.MaxBrowseContinuationPoints {
		return &ua.HistoryReadResult{StatusCode: ua.StatusBadNoContinuationPoints}
	}
	cp := randomBytes(16)
	sess.historyCPs[string(cp)] = &historyCP{node: node, pos: next}
	res.ContinuationPoint = cp
	return res
}

func historyError(err error) ua.StatusCode {
	if sc, ok := err.(ua.StatusCode); ok {
		return sc
	}
	return ua.StatusBadInternalError
}
