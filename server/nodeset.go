package server

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ka1hung/opcua/ua"
)

// The NodeSet2 XML schema (OPC 10000-6 Annex F), only as far as the server
// imports it. Unlike the schema package, attributes that have a default
// in the schema are pointers so that a missing attribute takes the default.
type xmlNodeSet struct {
	NamespaceURIs []string   `xml:"NamespaceUris>Uri"`
	Aliases       []xmlAlias `xml:"Aliases>Alias"`
	Nodes         []xmlNode  `xml:",any"`
}

type xmlAlias struct {
	Alias string `xml:"Alias,attr"`
	Value string `xml:",chardata"`
}

type xmlNode struct {
	XMLName         xml.Name
	NodeID          string         `xml:"NodeId,attr"`
	BrowseName      string         `xml:"BrowseName,attr"`
	WriteMask       uint32         `xml:"WriteMask,attr"`
	DisplayName     []xmlText      `xml:"DisplayName"`
	Description     []xmlText      `xml:"Description"`
	References      []xmlReference `xml:"References>Reference"`
	DataType        string         `xml:"DataType,attr"`
	ValueRank       *int32         `xml:"ValueRank,attr"`
	ArrayDims       string         `xml:"ArrayDimensions,attr"`
	AccessLevel     *uint8         `xml:"AccessLevel,attr"`
	MinSampling     float64        `xml:"MinimumSamplingInterval,attr"`
	Historizing     bool           `xml:"Historizing,attr"`
	EventNotifier   uint8          `xml:"EventNotifier,attr"`
	IsAbstract      bool           `xml:"IsAbstract,attr"`
	Symmetric       bool           `xml:"Symmetric,attr"`
	InverseName     []xmlText      `xml:"InverseName"`
	Executable      *bool          `xml:"Executable,attr"`
	ContainsNoLoops bool           `xml:"ContainsNoLoops,attr"`
	Value           *xmlAny        `xml:"Value"`
}

type xmlText struct {
	Locale string `xml:"Locale,attr"`
	Text   string `xml:",chardata"`
}

type xmlReference struct {
	ReferenceType string `xml:"ReferenceType,attr"`
	IsForward     *bool  `xml:"IsForward,attr"`
	Target        string `xml:",chardata"`
}

// xmlAny is a generic XML element tree, used for Value contents.
type xmlAny struct {
	XMLName  xml.Name
	Text     string   `xml:",chardata"`
	Children []xmlAny `xml:",any"`
}

func (a *xmlAny) child(name string) *xmlAny {
	for i := range a.Children {
		if a.Children[i].XMLName.Local == name {
			return &a.Children[i]
		}
	}
	return nil
}

func (a *xmlAny) text() string {
	if a == nil {
		return ""
	}
	return strings.TrimSpace(a.Text)
}

// nodeSetImporter maps the ids of one NodeSet into the address space.
type nodeSetImporter struct {
	space   *AddressSpace
	aliases map[string]string
	nsMap   []uint16 // NodeSet namespace index -> server namespace index
}

// importNodeSet adds the nodes of a NodeSet2 document. Namespaces of the
// document are registered in the server's namespace table, and node ids
// are remapped to the server's indices.
func (s *AddressSpace) importNodeSet(doc []byte) error {
	var set xmlNodeSet
	if err := xml.Unmarshal(doc, &set); err != nil {
		return fmt.Errorf("nodeset: %w", err)
	}
	imp := &nodeSetImporter{space: s, aliases: map[string]string{}, nsMap: []uint16{0}}
	for _, a := range set.Aliases {
		imp.aliases[a.Alias] = strings.TrimSpace(a.Value)
	}
	for _, uri := range set.NamespaceURIs {
		imp.nsMap = append(imp.nsMap, s.namespaceIndex(uri))
	}

	type pending struct {
		source  *ua.NodeID
		refType *ua.NodeID
		target  *ua.NodeID
		forward bool
	}
	var refs []pending
	for i := range set.Nodes {
		x := &set.Nodes[i]
		n, err := imp.node(x)
		if err != nil {
			return err
		}
		if n == nil {
			continue
		}
		if err := s.add(n); err != nil && err != ua.StatusBadNodeIDExists {
			return err
		}
		for _, r := range x.References {
			rt, err := imp.nodeID(r.ReferenceType)
			if err != nil {
				return fmt.Errorf("nodeset: %s: reference type %q: %w", x.NodeID, r.ReferenceType, err)
			}
			tgt, err := imp.nodeID(r.Target)
			if err != nil {
				return fmt.Errorf("nodeset: %s: target %q: %w", x.NodeID, r.Target, err)
			}
			refs = append(refs, pending{n.id, rt, tgt, r.IsForward == nil || *r.IsForward})
		}
	}
	s.mu.Lock()
	for _, r := range refs {
		if r.forward {
			s.addRefLocked(r.source, r.refType, r.target)
		} else {
			s.addRefLocked(r.target, r.refType, r.source)
		}
	}
	s.mu.Unlock()
	return nil
}

func (imp *nodeSetImporter) nodeID(s string) (*ua.NodeID, error) {
	s = strings.TrimSpace(s)
	if a, ok := imp.aliases[s]; ok {
		s = a
	}
	nid, err := ua.ParseNodeID(s)
	if err != nil {
		return nil, err
	}
	if ns := int(nid.Namespace()); ns != 0 {
		if ns >= len(imp.nsMap) {
			return nil, fmt.Errorf("namespace index %d not in NamespaceUris", ns)
		}
		if err := nid.SetNamespace(imp.nsMap[ns]); err != nil {
			return nil, err
		}
	}
	return nid, nil
}

func (imp *nodeSetImporter) qualifiedName(s string) *ua.QualifiedName {
	if i := strings.IndexByte(s, ':'); i > 0 {
		if ns, err := strconv.Atoi(s[:i]); err == nil && ns < len(imp.nsMap) {
			return &ua.QualifiedName{NamespaceIndex: imp.nsMap[ns], Name: s[i+1:]}
		}
	}
	return &ua.QualifiedName{Name: s}
}

func localizedText(ts []xmlText, fallback string) *ua.LocalizedText {
	if len(ts) == 0 {
		if fallback == "" {
			return nil
		}
		return ua.NewLocalizedText(fallback)
	}
	if ts[0].Locale != "" {
		return ua.NewLocalizedTextWithLocale(strings.TrimSpace(ts[0].Text), ts[0].Locale)
	}
	return ua.NewLocalizedText(strings.TrimSpace(ts[0].Text))
}

func (imp *nodeSetImporter) node(x *xmlNode) (*Node, error) {
	var class ua.NodeClass
	switch x.XMLName.Local {
	case "UAObject":
		class = ua.NodeClassObject
	case "UAVariable":
		class = ua.NodeClassVariable
	case "UAMethod":
		class = ua.NodeClassMethod
	case "UAView":
		class = ua.NodeClassView
	case "UAObjectType":
		class = ua.NodeClassObjectType
	case "UAVariableType":
		class = ua.NodeClassVariableType
	case "UADataType":
		class = ua.NodeClassDataType
	case "UAReferenceType":
		class = ua.NodeClassReferenceType
	default:
		return nil, nil // Aliases, NamespaceUris, Models, Extensions
	}
	nid, err := imp.nodeID(x.NodeID)
	if err != nil {
		return nil, fmt.Errorf("nodeset: node %q: %w", x.NodeID, err)
	}
	bn := imp.qualifiedName(x.BrowseName)
	n := &Node{
		id:          nid,
		class:       class,
		browseName:  bn,
		displayName: localizedText(x.DisplayName, bn.Name),
		description: localizedText(x.Description, ""),
		writeMask:   x.WriteMask,
	}
	switch class {
	case ua.NodeClassVariable, ua.NodeClassVariableType:
		n.valueRank = -1
		if x.ValueRank != nil {
			n.valueRank = *x.ValueRank
		}
		n.dataType = ua.NewNumericNodeID(0, 24) // BaseDataType
		if x.DataType != "" {
			if n.dataType, err = imp.nodeID(x.DataType); err != nil {
				return nil, fmt.Errorf("nodeset: %s: DataType: %w", x.NodeID, err)
			}
		}
		n.arrayDims = parseDims(x.ArrayDims)
		n.accessLevel = AccessLevelCurrentRead
		if x.AccessLevel != nil {
			n.accessLevel = *x.AccessLevel
		}
		n.minSampling = x.MinSampling
		n.historizing = x.Historizing
		n.isAbstract = x.IsAbstract
		if x.Value != nil && len(x.Value.Children) > 0 {
			if v := imp.variant(&x.Value.Children[0]); v != nil {
				n.value = &ua.DataValue{Value: v}
			}
		}
	case ua.NodeClassObject, ua.NodeClassView:
		n.eventNotifier = x.EventNotifier
		n.containsNoLoops = x.ContainsNoLoops
	case ua.NodeClassMethod:
		n.executable = x.Executable == nil || *x.Executable
	case ua.NodeClassReferenceType:
		n.isAbstract = x.IsAbstract
		n.symmetric = x.Symmetric
		n.inverseName = localizedText(x.InverseName, "")
	default:
		n.isAbstract = x.IsAbstract
	}
	return n, nil
}

func parseDims(s string) []uint32 {
	if s == "" {
		return nil
	}
	var out []uint32
	for _, p := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return nil
		}
		out = append(out, uint32(v))
	}
	return out
}

// variant decodes a Value element of the XML encoding (OPC 10000-6 §5.3).
// Types the server does not need are skipped (nil).
func (imp *nodeSetImporter) variant(a *xmlAny) *ua.Variant {
	name := a.XMLName.Local
	if strings.HasPrefix(name, "ListOf") {
		elem := strings.TrimPrefix(name, "ListOf")
		return imp.list(elem, a.Children)
	}
	v := imp.scalar(name, a)
	if v == nil {
		return nil
	}
	vv, err := ua.NewVariant(v)
	if err != nil {
		return nil
	}
	return vv
}

func (imp *nodeSetImporter) list(elem string, items []xmlAny) *ua.Variant {
	var out any
	switch elem {
	case "Boolean":
		out = collect(items, func(a *xmlAny) (bool, bool) { b, err := strconv.ParseBool(a.text()); return b, err == nil })
	case "Int32", "Int":
		out = collect(items, func(a *xmlAny) (int32, bool) {
			v, err := strconv.ParseInt(a.text(), 10, 32)
			return int32(v), err == nil
		})
	case "UInt32", "UInt":
		out = collect(items, func(a *xmlAny) (uint32, bool) {
			v, err := strconv.ParseUint(a.text(), 10, 32)
			return uint32(v), err == nil
		})
	case "Double":
		out = collect(items, func(a *xmlAny) (float64, bool) { v, err := strconv.ParseFloat(a.text(), 64); return v, err == nil })
	case "String":
		out = collect(items, func(a *xmlAny) (string, bool) { return a.Text, true })
	case "LocalizedText":
		out = collect(items, func(a *xmlAny) (*ua.LocalizedText, bool) { return xmlLocalizedText(a), true })
	case "QualifiedName":
		out = collect(items, func(a *xmlAny) (*ua.QualifiedName, bool) {
			return imp.qualifiedName(a.child("Name").text()), true
		})
	case "NodeId":
		out = collect(items, func(a *xmlAny) (*ua.NodeID, bool) {
			nid, err := imp.nodeID(a.child("Identifier").text())
			return nid, err == nil
		})
	case "ExtensionObject":
		out = collect(items, func(a *xmlAny) (*ua.ExtensionObject, bool) {
			eo := imp.extensionObject(a)
			return eo, eo != nil
		})
	default:
		return nil
	}
	v, err := ua.NewVariant(out)
	if err != nil {
		return nil
	}
	return v
}

func collect[T any](items []xmlAny, f func(*xmlAny) (T, bool)) []T {
	out := make([]T, 0, len(items))
	for i := range items {
		if v, ok := f(&items[i]); ok {
			out = append(out, v)
		}
	}
	return out
}

func (imp *nodeSetImporter) scalar(name string, a *xmlAny) any {
	t := a.text()
	switch name {
	case "Boolean":
		b, err := strconv.ParseBool(t)
		if err != nil {
			return nil
		}
		return b
	case "SByte":
		v, err := strconv.ParseInt(t, 10, 8)
		if err != nil {
			return nil
		}
		return int8(v)
	case "Byte":
		v, err := strconv.ParseUint(t, 10, 8)
		if err != nil {
			return nil
		}
		return uint8(v)
	case "Int16":
		v, err := strconv.ParseInt(t, 10, 16)
		if err != nil {
			return nil
		}
		return int16(v)
	case "UInt16":
		v, err := strconv.ParseUint(t, 10, 16)
		if err != nil {
			return nil
		}
		return uint16(v)
	case "Int32", "Int":
		v, err := strconv.ParseInt(t, 10, 32)
		if err != nil {
			return nil
		}
		return int32(v)
	case "UInt32", "UInt":
		v, err := strconv.ParseUint(t, 10, 32)
		if err != nil {
			return nil
		}
		return uint32(v)
	case "Int64":
		v, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return nil
		}
		return v
	case "UInt64":
		v, err := strconv.ParseUint(t, 10, 64)
		if err != nil {
			return nil
		}
		return v
	case "Float":
		v, err := strconv.ParseFloat(t, 32)
		if err != nil {
			return nil
		}
		return float32(v)
	case "Double":
		v, err := strconv.ParseFloat(t, 64)
		if err != nil {
			return nil
		}
		return v
	case "String":
		return a.Text
	case "DateTime":
		v, err := time.Parse(time.RFC3339Nano, t)
		if err != nil {
			return nil
		}
		return v
	case "ByteString":
		v, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(t), ""))
		if err != nil {
			return nil
		}
		return v
	case "LocalizedText":
		return xmlLocalizedText(a)
	case "QualifiedName":
		return imp.qualifiedName(a.child("Name").text())
	case "NodeId":
		nid, err := imp.nodeID(a.child("Identifier").text())
		if err != nil {
			return nil
		}
		return nid
	case "ExtensionObject":
		if eo := imp.extensionObject(a); eo != nil {
			return eo
		}
	}
	return nil
}

func xmlLocalizedText(a *xmlAny) *ua.LocalizedText {
	text := ""
	if t := a.child("Text"); t != nil {
		text = t.Text
	}
	if l := a.child("Locale"); l != nil && l.text() != "" {
		return ua.NewLocalizedTextWithLocale(text, l.text())
	}
	return ua.NewLocalizedText(text)
}

// extensionObject decodes the structures ns0 uses in values: Argument,
// EnumValueType and EUInformation.
func (imp *nodeSetImporter) extensionObject(a *xmlAny) *ua.ExtensionObject {
	body := a.child("Body")
	if body == nil || len(body.Children) == 0 {
		return nil
	}
	b := &body.Children[0]
	switch b.XMLName.Local {
	case "Argument":
		arg := &ua.Argument{
			Name:        b.child("Name").text(),
			ValueRank:   -1,
			Description: ua.NewLocalizedText(""),
		}
		if d := b.child("DataType"); d != nil {
			if nid, err := imp.nodeID(d.child("Identifier").text()); err == nil {
				arg.DataType = nid
			}
		}
		if arg.DataType == nil {
			arg.DataType = ua.NewNumericNodeID(0, 24)
		}
		if vr := b.child("ValueRank"); vr != nil {
			if v, err := strconv.ParseInt(vr.text(), 10, 32); err == nil {
				arg.ValueRank = int32(v)
			}
		}
		if ad := b.child("ArrayDimensions"); ad != nil {
			for i := range ad.Children {
				if v, err := strconv.ParseUint(ad.Children[i].text(), 10, 32); err == nil {
					arg.ArrayDimensions = append(arg.ArrayDimensions, uint32(v))
				}
			}
		}
		if d := b.child("Description"); d != nil {
			arg.Description = xmlLocalizedText(d)
		}
		return ua.NewExtensionObject(arg)
	case "EnumValueType":
		ev := &ua.EnumValueType{DisplayName: ua.NewLocalizedText(""), Description: ua.NewLocalizedText("")}
		if v, err := strconv.ParseInt(b.child("Value").text(), 10, 64); err == nil {
			ev.Value = v
		}
		if d := b.child("DisplayName"); d != nil {
			ev.DisplayName = xmlLocalizedText(d)
		}
		if d := b.child("Description"); d != nil {
			ev.Description = xmlLocalizedText(d)
		}
		return ua.NewExtensionObject(ev)
	}
	return nil
}
