package server

import (
	"context"
	"fmt"
	"reflect"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// MethodFunc implements a method. It gets the object the method is called
// on and the input arguments, already checked against the method's
// InputArguments, and returns the output arguments.
type MethodFunc func(ctx context.Context, who *Identity, object *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)

// MethodSpec describes a Method node.
type MethodSpec struct {
	NodeID      *ua.NodeID
	BrowseName  string
	DisplayName string
	Description string
	// InputArguments and OutputArguments describe the arguments; the
	// server checks calls against InputArguments.
	InputArguments  []*ua.Argument
	OutputArguments []*ua.Argument
	// CanCall decides per user; nil allows everyone (subject to
	// AnonymousReadOnly).
	CanCall func(*Identity) bool
	Handler MethodFunc
}

// AddMethod adds a method to an object.
func (s *Server) AddMethod(object *ua.NodeID, spec MethodSpec) (*Node, error) {
	if spec.NodeID == nil || spec.BrowseName == "" || spec.Handler == nil {
		return nil, fmt.Errorf("server: method needs NodeID, BrowseName and Handler")
	}
	o := s.space.Node(object)
	if o == nil || o.class != ua.NodeClassObject && o.class != ua.NodeClassObjectType {
		return nil, fmt.Errorf("server: %s is not an object: %w", object, ua.StatusBadParentNodeIDInvalid)
	}
	n := &Node{
		id:          spec.NodeID,
		class:       ua.NodeClassMethod,
		browseName:  &ua.QualifiedName{NamespaceIndex: spec.NodeID.Namespace(), Name: spec.BrowseName},
		displayName: ua.NewLocalizedText(orDefault(spec.DisplayName, spec.BrowseName)),
		description: ua.NewLocalizedText(spec.Description),
		executable:  true,
		canWrite:    spec.CanCall,
		call:        spec.Handler,
	}
	if err := s.space.add(n); err != nil {
		return nil, fmt.Errorf("server: add %s: %w", spec.NodeID, err)
	}
	s.space.addRef(object, refHasComponent, n.id)
	argType := ua.NewNumericNodeID(0, id.Argument)
	for _, a := range []struct {
		name string
		args []*ua.Argument
	}{{"InputArguments", spec.InputArguments}, {"OutputArguments", spec.OutputArguments}} {
		if len(a.args) == 0 {
			continue
		}
		eos := make([]*ua.ExtensionObject, len(a.args))
		for i, arg := range a.args {
			c := *arg
			if c.Description == nil {
				c.Description = ua.NewLocalizedText("")
			}
			if c.DataType == nil {
				c.DataType = ua.NewNumericNodeID(0, id.BaseDataType)
			}
			eos[i] = ua.NewExtensionObject(&c)
		}
		if err := s.addArrayProperty(n, a.name, argType, eos); err != nil {
			return nil, err
		}
	}
	return n, nil
}

func (s *Server) addArrayProperty(parent *Node, name string, dataType *ua.NodeID, value any) error {
	if err := s.addProperty(parent, name, dataType, value); err != nil {
		return err
	}
	p := s.space.Node(ua.NewStringNodeID(parent.id.Namespace(), propertyIDBase(parent.id)+"."+name))
	p.mu.Lock()
	p.valueRank = 1
	p.mu.Unlock()
	return nil
}

// SetMethodHandler sets the handler of an existing method node, such as a
// standard method of namespace 0.
func (s *Server) SetMethodHandler(method *ua.NodeID, h MethodFunc) error {
	n := s.space.Node(method)
	if n == nil || n.class != ua.NodeClassMethod {
		return fmt.Errorf("server: %s is not a method: %w", method, ua.StatusBadMethodInvalid)
	}
	n.mu.Lock()
	n.call = h
	n.mu.Unlock()
	return nil
}

func (s *Server) initMoreHandlers(reg func(uint16, Handler)) {
	reg(id.CallRequest_Encoding_DefaultBinary, s.callMethods)
	reg(id.HistoryReadRequest_Encoding_DefaultBinary, s.historyRead)
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.11.2
func (s *Server) callMethods(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.CallRequest)
	if err := s.checkOperations(len(req.MethodsToCall)); err != nil {
		return nil, err
	}
	who := r.Session.Identity()
	results := make([]*ua.CallMethodResult, len(req.MethodsToCall))
	for i, c := range req.MethodsToCall {
		results[i] = s.call(ctx, who, c)
	}
	return &ua.CallResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func (s *Server) call(ctx context.Context, who *Identity, c *ua.CallMethodRequest) *ua.CallMethodResult {
	fail := func(st ua.StatusCode) *ua.CallMethodResult { return &ua.CallMethodResult{StatusCode: st} }
	if c == nil || c.ObjectID == nil || c.MethodID == nil {
		return fail(ua.StatusBadNodeIDInvalid)
	}
	obj := s.space.Node(c.ObjectID)
	if obj == nil {
		return fail(ua.StatusBadNodeIDUnknown)
	}
	if obj.class != ua.NodeClassObject && obj.class != ua.NodeClassObjectType {
		return fail(ua.StatusBadNodeIDInvalid)
	}
	m := s.space.Node(c.MethodID)
	if m == nil || m.class != ua.NodeClassMethod {
		return fail(ua.StatusBadMethodInvalid)
	}
	if !s.methodOf(obj, m) {
		return fail(ua.StatusBadMethodInvalid)
	}
	m.mu.RLock()
	exe, h := m.executable, m.call
	m.mu.RUnlock()
	if !exe {
		return fail(ua.StatusBadNotExecutable)
	}
	if !s.userExecutable(m, who) {
		return fail(ua.StatusBadUserAccessDenied)
	}
	if h == nil {
		return fail(ua.StatusBadNotImplemented)
	}

	args, argResults, st := s.checkArguments(m, c.InputArguments)
	if st != ua.StatusOK {
		return &ua.CallMethodResult{StatusCode: st, InputArgumentResults: argResults}
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.limits.WriteTimeout)
	defer cancel()
	type out struct {
		vals []*ua.Variant
		st   ua.StatusCode
	}
	done := make(chan out, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.logError("panic in method %s: %v", m.id, p)
				done <- out{nil, ua.StatusBadInternalError}
			}
		}()
		vals, st := h(ctx, who, obj.id, args)
		done <- out{vals, st}
	}()
	select {
	case o := <-done:
		res := &ua.CallMethodResult{StatusCode: o.st, OutputArguments: o.vals}
		if res.OutputArguments == nil {
			res.OutputArguments = []*ua.Variant{}
		}
		return res
	case <-ctx.Done():
		return fail(ua.StatusBadTimeout)
	}
}

// methodOf reports whether m is a method of obj: a component of the object
// itself or of its type or a supertype (OPC 10000-4 §5.11.2).
func (s *Server) methodOf(obj, m *Node) bool {
	has := func(n *Node) bool {
		for _, r := range s.space.refsOf(n) {
			if r.forward && sameID(r.target, m.id) && s.space.isSubtype(r.refType, refHasComponent) {
				return true
			}
		}
		return false
	}
	if has(obj) {
		return true
	}
	t := obj
	if obj.class == ua.NodeClassObject {
		td := s.space.typeDefinition(obj)
		if td == nil {
			return false
		}
		t = s.space.Node(td)
	}
	for depth := 0; t != nil && depth < 32; depth++ {
		if has(t) {
			return true
		}
		var parent *ua.NodeID
		for _, r := range s.space.refsOf(t) {
			if !r.forward && r.refType.Namespace() == 0 && r.refType.IntID() == id.HasSubtype {
				parent = r.target
			}
		}
		if parent == nil {
			return false
		}
		t = s.space.Node(parent)
	}
	return false
}

// inputArguments returns the InputArguments property of a method.
func (s *Server) inputArguments(m *Node) []*ua.Argument {
	p := s.space.child(m, &ua.QualifiedName{Name: "InputArguments"})
	if p == nil {
		return nil
	}
	dv := p.dataValue()
	if dv.Value == nil {
		return nil
	}
	eos, _ := dv.Value.Value().([]*ua.ExtensionObject)
	out := make([]*ua.Argument, 0, len(eos))
	for _, eo := range eos {
		if a, ok := eo.Value.(*ua.Argument); ok {
			out = append(out, a)
		}
	}
	return out
}

// checkArguments checks call arguments against InputArguments and
// converts numbers like a lenient write does.
func (s *Server) checkArguments(m *Node, in []*ua.Variant) ([]*ua.Variant, []ua.StatusCode, ua.StatusCode) {
	want := s.inputArguments(m)
	if len(in) < len(want) {
		return nil, nil, ua.StatusBadArgumentsMissing
	}
	if len(in) > len(want) {
		return nil, nil, ua.StatusBadTooManyArguments
	}
	out := make([]*ua.Variant, len(in))
	results := make([]ua.StatusCode, len(in))
	bad := false
	for i, a := range want {
		v := in[i]
		if v == nil || v.Value() == nil {
			// A null value is allowed for an argument that may be empty,
			// such as a ByteString or String.
			out[i] = v
			continue
		}
		cv, st := s.convertForWrite(a.DataType, a.ValueRank, v)
		if st != ua.StatusOK {
			results[i] = ua.StatusBadTypeMismatch
			bad = true
			continue
		}
		out[i] = cv
	}
	if bad {
		return nil, results, ua.StatusBadInvalidArgument
	}
	return out, results, ua.StatusOK
}

var _ = reflect.TypeOf
