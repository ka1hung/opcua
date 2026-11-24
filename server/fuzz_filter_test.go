package server

import (
	"sync"
	"testing"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

var (
	fuzzSrvOnce sync.Once
	fuzzSrv     *Server
)

// FuzzEventFilter feeds arbitrary ContentFilters, as a client sends them,
// to the where clause check and, if it passes, to the evaluator. Neither
// may panic or loop.
func FuzzEventFilter(f *testing.F) {
	fuzzSrvOnce.Do(func() { fuzzSrv = New() })
	seed := &ua.ContentFilter{Elements: []*ua.ContentFilterElement{
		{FilterOperator: ua.FilterOperatorAnd, FilterOperands: []*ua.ExtensionObject{
			ua.NewExtensionObject(&ua.ElementOperand{Index: 1}), ua.NewExtensionObject(&ua.ElementOperand{Index: 2})}},
		{FilterOperator: ua.FilterOperatorGreaterThan, FilterOperands: []*ua.ExtensionObject{
			ua.NewExtensionObject(&ua.SimpleAttributeOperand{TypeDefinitionID: ua.NewNumericNodeID(0, id.BaseEventType),
				BrowsePath: []*ua.QualifiedName{{Name: "Severity"}}, AttributeID: ua.AttributeIDValue}),
			ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant(uint16(500))})}},
		{FilterOperator: ua.FilterOperatorLike, FilterOperands: []*ua.ExtensionObject{
			ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant("abc")}),
			ua.NewExtensionObject(&ua.LiteralOperand{Value: ua.MustVariant("a[^x]%")})}},
	}}
	b, err := ua.Encode(seed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		var cf ua.ContentFilter
		if _, err := ua.Decode(b, &cf); err != nil {
			return
		}
		if _, ok := fuzzSrv.checkWhere(&cf); !ok {
			return
		}
		d, err := fuzzSrv.eventData(&Event{Message: "m", Severity: 600})
		if err != nil {
			t.Fatal(err)
		}
		if len(cf.Elements) > 0 {
			fuzzSrv.evalFilter(&cf, 0, d, 0)
		}
	})
}
