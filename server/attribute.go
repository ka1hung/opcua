package server

import (
	"context"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ka1hung/opcua/ua"
)

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.11.2
func (s *Server) read(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.ReadRequest)
	if err := s.checkOperations(len(req.NodesToRead)); err != nil {
		return nil, err
	}
	if req.MaxAge < 0 {
		return nil, ua.StatusBadMaxAgeInvalid
	}
	if req.TimestampsToReturn > ua.TimestampsToReturnNeither {
		return nil, ua.StatusBadTimestampsToReturnInvalid
	}
	who := r.Session.Identity()
	results := make([]*ua.DataValue, len(req.NodesToRead))
	for i, rv := range req.NodesToRead {
		results[i] = s.readAttribute(who, rv, req.TimestampsToReturn)
	}
	return &ua.ReadResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func badValue(status ua.StatusCode) *ua.DataValue {
	dv := &ua.DataValue{Status: status}
	dv.UpdateMask()
	return dv
}

func variantOf(v any) *ua.DataValue {
	vv, err := ua.NewVariant(v)
	if err != nil {
		return badValue(ua.StatusBadInternalError)
	}
	dv := &ua.DataValue{Value: vv}
	dv.UpdateMask()
	return dv
}

// readAttribute reads one attribute for a user (OPC 10000-4 §5.11.2).
func (s *Server) readAttribute(who *Identity, rv *ua.ReadValueID, ttr ua.TimestampsToReturn) *ua.DataValue {
	if rv == nil || rv.NodeID == nil {
		return badValue(ua.StatusBadNodeIDInvalid)
	}
	n := s.space.Node(rv.NodeID)
	if n == nil {
		return badValue(ua.StatusBadNodeIDUnknown)
	}
	if rv.DataEncoding != nil && rv.DataEncoding.Name != "" && rv.DataEncoding.Name != "Default Binary" {
		return badValue(ua.StatusBadDataEncodingInvalid)
	}
	if rv.AttributeID != ua.AttributeIDValue && rv.IndexRange != "" {
		return badValue(ua.StatusBadIndexRangeNoData)
	}

	n.mu.RLock()
	class := n.class
	isVar := class == ua.NodeClassVariable || class == ua.NodeClassVariableType
	isType := class == ua.NodeClassObjectType || class == ua.NodeClassVariableType ||
		class == ua.NodeClassReferenceType || class == ua.NodeClassDataType
	var dv *ua.DataValue
	switch rv.AttributeID {
	case ua.AttributeIDNodeID:
		dv = variantOf(n.id)
	case ua.AttributeIDNodeClass:
		dv = variantOf(int32(n.class))
	case ua.AttributeIDBrowseName:
		dv = variantOf(n.browseName)
	case ua.AttributeIDDisplayName:
		dv = variantOf(orEmpty(n.displayName))
	case ua.AttributeIDDescription:
		dv = variantOf(orEmpty(n.description))
	case ua.AttributeIDWriteMask:
		dv = variantOf(n.writeMask)
	case ua.AttributeIDUserWriteMask:
		dv = variantOf(n.writeMask)
	case ua.AttributeIDIsAbstract:
		if !isType {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.isAbstract)
		}
	case ua.AttributeIDSymmetric:
		if class != ua.NodeClassReferenceType {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.symmetric)
		}
	case ua.AttributeIDInverseName:
		if class != ua.NodeClassReferenceType {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(orEmpty(n.inverseName))
		}
	case ua.AttributeIDContainsNoLoops:
		if class != ua.NodeClassView {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.containsNoLoops)
		}
	case ua.AttributeIDEventNotifier:
		if class != ua.NodeClassObject && class != ua.NodeClassView {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.eventNotifier)
		}
	case ua.AttributeIDDataType:
		if !isVar {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.dataType)
		}
	case ua.AttributeIDValueRank:
		if !isVar {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.valueRank)
		}
	case ua.AttributeIDArrayDimensions:
		if !isVar {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else if n.arrayDims == nil {
			dv = variantOf(nil)
		} else {
			dv = variantOf(append([]uint32(nil), n.arrayDims...))
		}
	case ua.AttributeIDAccessLevel:
		if class != ua.NodeClassVariable {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.accessLevel)
		}
	case ua.AttributeIDMinimumSamplingInterval:
		if class != ua.NodeClassVariable {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.minSampling)
		}
	case ua.AttributeIDHistorizing:
		if class != ua.NodeClassVariable {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.historizing)
		}
	case ua.AttributeIDExecutable:
		if class != ua.NodeClassMethod {
			dv = badValue(ua.StatusBadAttributeIDInvalid)
		} else {
			dv = variantOf(n.executable)
		}
	case ua.AttributeIDUserAccessLevel, ua.AttributeIDUserExecutable, ua.AttributeIDValue:
		// computed below, outside the node lock
	default:
		dv = badValue(ua.StatusBadAttributeIDInvalid)
	}
	n.mu.RUnlock()
	if dv != nil {
		return dv
	}

	switch rv.AttributeID {
	case ua.AttributeIDUserAccessLevel:
		if class != ua.NodeClassVariable {
			return badValue(ua.StatusBadAttributeIDInvalid)
		}
		return variantOf(s.userAccessLevel(n, who))
	case ua.AttributeIDUserExecutable:
		if class != ua.NodeClassMethod {
			return badValue(ua.StatusBadAttributeIDInvalid)
		}
		return variantOf(s.userExecutable(n, who))
	}

	// Value
	if !isVar {
		return badValue(ua.StatusBadAttributeIDInvalid)
	}
	if class == ua.NodeClassVariable {
		if s.userAccessLevel(n, who)&AccessLevelCurrentRead == 0 {
			n.mu.RLock()
			al := n.accessLevel
			n.mu.RUnlock()
			if al&AccessLevelCurrentRead == 0 {
				return badValue(ua.StatusBadNotReadable)
			}
			return badValue(ua.StatusBadUserAccessDenied)
		}
	}
	dv = n.dataValue()
	if rv.IndexRange != "" {
		v, st := applyIndexRange(dv.Value, rv.IndexRange)
		if st != ua.StatusOK {
			return badValue(st)
		}
		dv.Value = v
	}
	return withTimestamps(dv, ttr)
}

func orEmpty(t *ua.LocalizedText) *ua.LocalizedText {
	if t == nil {
		return ua.NewLocalizedText("")
	}
	return t
}

// withTimestamps keeps the timestamps the client asked for.
func withTimestamps(dv *ua.DataValue, ttr ua.TimestampsToReturn) *ua.DataValue {
	c := *dv
	if c.ServerTimestamp.IsZero() {
		c.ServerTimestamp = time.Now()
	}
	switch ttr {
	case ua.TimestampsToReturnSource:
		c.ServerTimestamp = time.Time{}
	case ua.TimestampsToReturnServer:
		c.SourceTimestamp = time.Time{}
	case ua.TimestampsToReturnNeither:
		c.SourceTimestamp, c.ServerTimestamp = time.Time{}, time.Time{}
	}
	c.SourcePicoseconds, c.ServerPicoseconds = 0, 0
	c.UpdateMask()
	return &c
}

// userAccessLevel is the AccessLevel as it applies to a user.
func (s *Server) userAccessLevel(n *Node, who *Identity) byte {
	n.mu.RLock()
	al, canRead, canWrite := n.accessLevel, n.canRead, n.canWrite
	n.mu.RUnlock()
	if canRead != nil && !canRead(who) {
		al &^= AccessLevelCurrentRead | AccessLevelHistoryRead
	}
	if who.Anonymous() && s.cfg.anonymousReadOnly {
		al &^= AccessLevelCurrentWrite | AccessLevelHistoryWrite
	}
	if canWrite != nil && !canWrite(who) {
		al &^= AccessLevelCurrentWrite
	}
	return al
}

func (s *Server) userExecutable(n *Node, who *Identity) bool {
	n.mu.RLock()
	exe, canCall, readOnly := n.executable, n.canWrite, n.readOnlyCall
	n.mu.RUnlock()
	if !exe {
		return false
	}
	if who.Anonymous() && s.cfg.anonymousReadOnly && !readOnly {
		return false
	}
	return canCall == nil || canCall(who)
}

// parseIndexRange parses a NumericRange of one dimension: "i" or "i:j"
// (OPC 10000-4 §7.27).
func parseIndexRange(r string) (lo, hi int, ok bool) {
	if strings.Contains(r, ",") {
		return 0, 0, false // more dimensions are not supported
	}
	parts := strings.Split(r, ":")
	if len(parts) > 2 {
		return 0, 0, false
	}
	a, err := strconv.Atoi(parts[0])
	if err != nil || a < 0 {
		return 0, 0, false
	}
	if len(parts) == 1 {
		return a, a, true
	}
	b, err := strconv.Atoi(parts[1])
	if err != nil || b <= a {
		return 0, 0, false
	}
	return a, b, true
}

// rangeEnd is the end, exclusive, of the slice the last index hi selects
// from n elements. It does not compute hi+1 for an hi at or past the end,
// which a client may set to the largest int.
func rangeEnd(hi, n int) int {
	if hi >= n-1 {
		return n
	}
	return hi + 1
}

// applyIndexRange returns the part of an array, String or ByteString
// value selected by a one-dimensional index range.
func applyIndexRange(v *ua.Variant, r string) (*ua.Variant, ua.StatusCode) {
	lo, hi, ok := parseIndexRange(r)
	if !ok {
		return nil, ua.StatusBadIndexRangeInvalid
	}
	if v == nil || v.Value() == nil {
		return nil, ua.StatusBadIndexRangeNoData
	}
	switch x := v.Value().(type) {
	case string:
		if lo >= len(x) {
			return nil, ua.StatusBadIndexRangeNoData
		}
		out, _ := ua.NewVariant(x[lo:rangeEnd(hi, len(x))])
		return out, ua.StatusOK
	case []byte:
		if lo >= len(x) {
			return nil, ua.StatusBadIndexRangeNoData
		}
		out, _ := ua.NewVariant(append([]byte(nil), x[lo:rangeEnd(hi, len(x))]...))
		return out, ua.StatusOK
	}
	rv := reflect.ValueOf(v.Value())
	if rv.Kind() != reflect.Slice {
		return nil, ua.StatusBadIndexRangeNoData
	}
	if lo >= rv.Len() {
		return nil, ua.StatusBadIndexRangeNoData
	}
	part := reflect.MakeSlice(rv.Type(), 0, 0)
	part = reflect.AppendSlice(part, rv.Slice(lo, rangeEnd(hi, rv.Len())))
	out, err := ua.NewVariant(part.Interface())
	if err != nil {
		return nil, ua.StatusBadIndexRangeNoData
	}
	return out, ua.StatusOK
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.11.4
func (s *Server) write(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.WriteRequest)
	if err := s.checkOperations(len(req.NodesToWrite)); err != nil {
		return nil, err
	}
	who := r.Session.Identity()
	results := make([]ua.StatusCode, len(req.NodesToWrite))
	for i, wv := range req.NodesToWrite {
		results[i] = s.writeAttribute(ctx, who, wv)
	}
	return &ua.WriteResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func (s *Server) writeAttribute(ctx context.Context, who *Identity, wv *ua.WriteValue) ua.StatusCode {
	if wv == nil || wv.NodeID == nil {
		return ua.StatusBadNodeIDInvalid
	}
	n := s.space.Node(wv.NodeID)
	if n == nil {
		return ua.StatusBadNodeIDUnknown
	}
	if wv.AttributeID != ua.AttributeIDValue {
		if wv.AttributeID == ua.AttributeIDInvalid || wv.AttributeID > ua.AttributeIDAccessLevelEx {
			return ua.StatusBadAttributeIDInvalid
		}
		return ua.StatusBadNotWritable
	}
	if n.class != ua.NodeClassVariable {
		return ua.StatusBadNotWritable
	}
	n.mu.RLock()
	al, dataType, valueRank, handler := n.accessLevel, n.dataType, n.valueRank, n.onWrite
	n.mu.RUnlock()
	if al&AccessLevelCurrentWrite == 0 {
		return ua.StatusBadNotWritable
	}
	if s.userAccessLevel(n, who)&AccessLevelCurrentWrite == 0 {
		return ua.StatusBadUserAccessDenied
	}
	if wv.IndexRange != "" {
		return ua.StatusBadWriteNotSupported
	}
	if wv.Value == nil || wv.Value.Value == nil || wv.Value.Value.Value() == nil {
		return ua.StatusBadTypeMismatch
	}
	value, st := s.convertForWrite(dataType, valueRank, wv.Value.Value)
	if st != ua.StatusOK {
		return st
	}

	if handler == nil {
		s.writeMu.RLock()
		handler = s.onWrite
		s.writeMu.RUnlock()
	}
	if handler != nil {
		st = s.callWrite(ctx, handler, who, n.id, value)
		if !isGood(st) {
			return st
		}
	}
	now := time.Now()
	n.setValue(&ua.DataValue{Value: value, SourceTimestamp: now, ServerTimestamp: now})
	return st
}

// callWrite runs a write callback bounded by WriteTimeout.
func (s *Server) callWrite(ctx context.Context, h WriteFunc, who *Identity, nid *ua.NodeID, v *ua.Variant) ua.StatusCode {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.limits.WriteTimeout)
	defer cancel()
	done := make(chan ua.StatusCode, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.logError("panic in write callback for %s: %v", nid, p)
				done <- ua.StatusBadInternalError
			}
		}()
		done <- h(ctx, who, nid, v)
	}()
	select {
	case st := <-done:
		return st
	case <-ctx.Done():
		return ua.StatusBadTimeout
	}
}

func isGood(st ua.StatusCode) bool { return uint32(st)&0xC0000000 == 0 }

// builtinOf returns the built-in type a DataType resolves to, or 0 for
// BaseDataType and for abstract types that allow several built-in types.
// numeric reports Number and its abstract subtypes.
func (s *Server) builtinOf(dt *ua.NodeID) (t ua.TypeID, numeric bool) {
	cur := dt
	for depth := 0; cur != nil && depth < 32; depth++ {
		if cur.Namespace() == 0 {
			switch i := cur.IntID(); {
			case i == 24: // BaseDataType: any value
				return 0, false
			case i >= 1 && i <= 25:
				return ua.TypeID(i), false
			case i == 26 || i == 27 || i == 28: // Number, Integer, UInteger
				return 0, true
			case i == 29: // Enumeration
				return ua.TypeIDInt32, false
			}
		}
		n := s.space.Node(cur)
		if n == nil {
			return 0, false
		}
		var parent *ua.NodeID
		for _, r := range s.space.refsOf(n) {
			if !r.forward && r.refType.Namespace() == 0 && r.refType.IntID() == 45 { // HasSubtype
				parent = r.target
			}
		}
		cur = parent
	}
	return 0, false
}

// convertForWrite checks a written value against the variable's DataType
// and ValueRank and, with LenientWriteTypes, converts scalar numbers and
// Booleans to the variable's type.
func (s *Server) convertForWrite(dataType *ua.NodeID, valueRank int32, v *ua.Variant) (*ua.Variant, ua.StatusCode) {
	isArray := v.ArrayLength() > 0 || reflect.ValueOf(v.Value()).Kind() == reflect.Slice && v.Type() != ua.TypeIDByteString
	switch {
	case valueRank == -1 && isArray, valueRank >= 1 && !isArray, valueRank == 0 && !isArray:
		return nil, ua.StatusBadTypeMismatch
	}

	want, numeric := s.builtinOf(dataType)
	if want == 0 {
		if numeric && !isNumericType(v.Type()) {
			return nil, ua.StatusBadTypeMismatch
		}
		return v, ua.StatusOK
	}
	if v.Type() == want {
		return v, ua.StatusOK
	}
	if isArray || !s.cfg.lenientWriteTypes || !isConvertible(v.Type()) || !isConvertible(want) {
		return nil, ua.StatusBadTypeMismatch
	}
	return convertScalar(v, want)
}

func isNumericType(t ua.TypeID) bool {
	return t >= ua.TypeIDSByte && t <= ua.TypeIDDouble
}

func isConvertible(t ua.TypeID) bool {
	return t == ua.TypeIDBoolean || isNumericType(t)
}

func convertScalar(v *ua.Variant, want ua.TypeID) (*ua.Variant, ua.StatusCode) {
	var f float64
	switch x := v.Value().(type) {
	case bool:
		if x {
			f = 1
		}
	case int8:
		f = float64(x)
	case uint8:
		f = float64(x)
	case int16:
		f = float64(x)
	case uint16:
		f = float64(x)
	case int32:
		f = float64(x)
	case uint32:
		f = float64(x)
	case int64:
		f = float64(x)
	case uint64:
		f = float64(x)
	case float32:
		f = float64(x)
	case float64:
		f = x
	default:
		return nil, ua.StatusBadTypeMismatch
	}
	if math.IsNaN(f) && want != ua.TypeIDFloat && want != ua.TypeIDDouble {
		return nil, ua.StatusBadOutOfRange
	}
	isInt := want != ua.TypeIDFloat && want != ua.TypeIDDouble && want != ua.TypeIDBoolean
	if isInt && f != math.Trunc(f) {
		return nil, ua.StatusBadTypeMismatch
	}
	inRange := func(lo, hi float64) bool { return f >= lo && f <= hi }
	var out any
	switch want {
	case ua.TypeIDBoolean:
		if f != 0 && f != 1 {
			return nil, ua.StatusBadOutOfRange
		}
		out = f == 1
	case ua.TypeIDSByte:
		if !inRange(math.MinInt8, math.MaxInt8) {
			return nil, ua.StatusBadOutOfRange
		}
		out = int8(f)
	case ua.TypeIDByte:
		if !inRange(0, math.MaxUint8) {
			return nil, ua.StatusBadOutOfRange
		}
		out = uint8(f)
	case ua.TypeIDInt16:
		if !inRange(math.MinInt16, math.MaxInt16) {
			return nil, ua.StatusBadOutOfRange
		}
		out = int16(f)
	case ua.TypeIDUint16:
		if !inRange(0, math.MaxUint16) {
			return nil, ua.StatusBadOutOfRange
		}
		out = uint16(f)
	case ua.TypeIDInt32:
		if !inRange(math.MinInt32, math.MaxInt32) {
			return nil, ua.StatusBadOutOfRange
		}
		out = int32(f)
	case ua.TypeIDUint32:
		if !inRange(0, math.MaxUint32) {
			return nil, ua.StatusBadOutOfRange
		}
		out = uint32(f)
	case ua.TypeIDInt64:
		if !inRange(math.MinInt64, math.MaxInt64) {
			return nil, ua.StatusBadOutOfRange
		}
		out = int64(f)
	case ua.TypeIDUint64:
		if !inRange(0, math.MaxUint64) {
			return nil, ua.StatusBadOutOfRange
		}
		out = uint64(f)
	case ua.TypeIDFloat:
		if !math.IsInf(f, 0) && !math.IsNaN(f) && !inRange(-math.MaxFloat32, math.MaxFloat32) {
			return nil, ua.StatusBadOutOfRange
		}
		out = float32(f)
	case ua.TypeIDDouble:
		out = f
	default:
		return nil, ua.StatusBadTypeMismatch
	}
	nv, err := ua.NewVariant(out)
	if err != nil {
		return nil, ua.StatusBadTypeMismatch
	}
	return nv, ua.StatusOK
}

// setValue stores a value and hands it to the monitored items of the node.
func (n *Node) setValue(dv *ua.DataValue) {
	n.mu.Lock()
	n.value = dv
	items := make([]*monitoredItem, 0, len(n.items))
	for it := range n.items {
		items = append(items, it)
	}
	n.mu.Unlock()
	for _, it := range items {
		it.onValue(dv)
	}
}
