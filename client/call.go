package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// Argument describes one argument of a method.
type Argument struct {
	Name        string
	DataType    string // e.g. "String", "Double"; see TypeName
	ValueRank   int32  // -1 scalar
	Description string

	dataType *ua.NodeID
}

type methodArgs struct{ in, out []Argument }

// MethodArguments reads a method's input and output arguments.
func (c *Client) MethodArguments(ctx context.Context, method string) (in, out []Argument, err error) {
	ma, err := c.methodArgs(ctx, method)
	if err != nil {
		return nil, nil, err
	}
	return ma.in, ma.out, nil
}

func (c *Client) methodArgs(ctx context.Context, method string) (methodArgs, error) {
	c.mu.Lock()
	ma, ok := c.methods[method]
	c.mu.Unlock()
	if ok {
		return ma, nil
	}
	nid, err := parse(method)
	if err != nil {
		return ma, err
	}
	bctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.c.Browse(bctx, &ua.BrowseRequest{NodesToBrowse: []*ua.BrowseDescription{{
		NodeID: nid, BrowseDirection: ua.BrowseDirectionForward,
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasProperty), IncludeSubtypes: true, ResultMask: 0x3f,
	}}})
	if err != nil {
		return ma, fmt.Errorf("client: arguments of %s: %w", method, err)
	}
	if len(resp.Results) != 1 {
		return ma, fmt.Errorf("client: arguments of %s: short response", method)
	}
	if st := resp.Results[0].StatusCode; st != ua.StatusOK {
		return ma, fmt.Errorf("client: arguments of %s: %w", method, st)
	}
	for _, r := range resp.Results[0].References {
		var dst *[]Argument
		switch r.BrowseName.Name {
		case "InputArguments":
			dst = &ma.in
		case "OutputArguments":
			dst = &ma.out
		default:
			continue
		}
		rresp, err := c.c.Read(bctx, &ua.ReadRequest{NodesToRead: []*ua.ReadValueID{
			{NodeID: r.NodeID.NodeID, AttributeID: ua.AttributeIDValue},
		}})
		if err != nil {
			return ma, fmt.Errorf("client: arguments of %s: %w", method, err)
		}
		if len(rresp.Results) != 1 || rresp.Results[0].Value == nil {
			continue
		}
		eos, _ := rresp.Results[0].Value.Value().([]*ua.ExtensionObject)
		for _, eo := range eos {
			a, ok := eo.Value.(*ua.Argument)
			if !ok || a == nil {
				continue
			}
			arg := Argument{Name: a.Name, DataType: TypeName(a.DataType), ValueRank: a.ValueRank, dataType: a.DataType}
			if a.Description != nil {
				arg.Description = a.Description.Text
			}
			*dst = append(*dst, arg)
		}
	}
	c.mu.Lock()
	c.methods[method] = ma
	c.mu.Unlock()
	return ma, nil
}

// CallError reports a method call the server refused. Args holds the
// status of each input argument when the server checked them.
type CallError struct {
	Method string
	Status ua.StatusCode
	Args   []ua.StatusCode
}

func (e *CallError) Error() string {
	var bad []string
	for i, st := range e.Args {
		if st != ua.StatusOK {
			bad = append(bad, fmt.Sprintf("argument %d: %v", i+1, st))
		}
	}
	if len(bad) > 0 {
		return fmt.Sprintf("client: call %s: %v (%s)", e.Method, e.Status, strings.Join(bad, "; "))
	}
	return fmt.Sprintf("client: call %s: %v", e.Method, e.Status)
}

func (e *CallError) Unwrap() error { return e.Status }

// Call calls a method of an object. Each argument is converted to the
// type of the method's input argument when that is a built-in type, so
// text from a form works: Call(ctx, obj, m, "reason", "3.5"). It returns
// the output arguments; a refused call returns a *CallError.
func (c *Client) Call(ctx context.Context, object, method string, args ...any) ([]any, error) {
	oid, err := parse(object)
	if err != nil {
		return nil, err
	}
	mid, err := parse(method)
	if err != nil {
		return nil, err
	}
	ma, err := c.methodArgs(ctx, method)
	if err != nil {
		return nil, err
	}
	in := make([]*ua.Variant, len(args))
	for i, a := range args {
		if i < len(ma.in) {
			if bt := builtinOf(ma.in[i].dataType); bt != 0 && ma.in[i].ValueRank < 0 {
				conv, err := toBuiltin(a, bt)
				if err != nil {
					return nil, fmt.Errorf("client: call %s: argument %d (%s): %w", method, i+1, ma.in[i].Name, err)
				}
				a = conv
			}
		}
		v, err := ua.NewVariant(a)
		if err != nil {
			return nil, fmt.Errorf("client: call %s: argument %d: %w", method, i+1, err)
		}
		in[i] = v
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	res, err := c.c.Call(cctx, &ua.CallMethodRequest{ObjectID: oid, MethodID: mid, InputArguments: in})
	if err != nil {
		return nil, fmt.Errorf("client: call %s: %w", method, err)
	}
	if res.StatusCode != ua.StatusOK {
		return nil, &CallError{Method: method, Status: res.StatusCode, Args: res.InputArgumentResults}
	}
	out := make([]any, len(res.OutputArguments))
	for i, v := range res.OutputArguments {
		if v != nil {
			out[i] = v.Value()
		}
	}
	return out, nil
}

// builtinOf maps a standard DataType node to the built-in type toBuiltin
// converts to, 0 for others (their values are passed on as given).
func builtinOf(dt *ua.NodeID) ua.TypeID {
	if dt == nil || dt.Namespace() != 0 {
		return 0
	}
	switch i := dt.IntID(); {
	case i >= 1 && i <= 13 || i == 15: // Boolean ... DateTime, ByteString
		return ua.TypeID(i)
	case i == 290:
		return ua.TypeIDDouble
	case i == 294:
		return ua.TypeIDDateTime
	case i == 288 || i == 289:
		return ua.TypeIDUint32
	}
	return 0
}
