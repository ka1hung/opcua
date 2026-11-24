package server

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// Access level bits (OPC 10000-3 §8.57).
const (
	AccessLevelCurrentRead    byte = 0x01
	AccessLevelCurrentWrite   byte = 0x02
	AccessLevelHistoryRead    byte = 0x04
	AccessLevelHistoryWrite   byte = 0x08
	AccessLevelSemanticChange byte = 0x10
	AccessLevelStatusWrite    byte = 0x20
	AccessLevelTimestampWrite byte = 0x40
)

// EventNotifier bits (OPC 10000-3 §8.59).
const (
	EventNotifierSubscribeToEvents byte = 0x01
	EventNotifierHistoryRead       byte = 0x04
	EventNotifierHistoryWrite      byte = 0x08
)

// Range is an EURange: the expected value range of an analog variable.
type Range struct{ Low, High float64 }

type reference struct {
	refType *ua.NodeID
	target  *ua.NodeID
	forward bool
}

// WriteFunc handles a write of a variable's Value. It returns the result
// for the client; on Good the server stores the value.
type WriteFunc func(ctx context.Context, who *Identity, node *ua.NodeID, value *ua.Variant) ua.StatusCode

// Node is a node of the address space.
type Node struct {
	mu sync.RWMutex

	id          *ua.NodeID
	class       ua.NodeClass
	browseName  *ua.QualifiedName
	displayName *ua.LocalizedText
	description *ua.LocalizedText
	writeMask   uint32

	// Variable and VariableType
	value       *ua.DataValue
	valueFunc   func() *ua.DataValue
	dataType    *ua.NodeID
	valueRank   int32
	arrayDims   []uint32
	accessLevel byte
	minSampling float64
	historizing bool
	euRange     *Range
	canRead     func(*Identity) bool
	canWrite    func(*Identity) bool
	onWrite     WriteFunc

	// Object and View
	eventNotifier   byte
	containsNoLoops bool

	// ObjectType, VariableType, ReferenceType, DataType
	isAbstract  bool
	symmetric   bool
	inverseName *ua.LocalizedText

	// Method
	executable bool
	call       MethodFunc
	// readOnlyCall marks a method that changes nothing, which anonymous
	// users may call even when AnonymousReadOnly is set.
	readOnlyCall bool

	// guarded by AddressSpace.mu
	refs []reference

	// monitored items of the Value attribute; guarded by mu
	items map[*monitoredItem]struct{}
}

// ID returns the node's id.
func (n *Node) ID() *ua.NodeID { return n.id }

// NodeClass returns the node's class.
func (n *Node) NodeClass() ua.NodeClass { return n.class }

// BrowseName returns the node's browse name.
func (n *Node) BrowseName() *ua.QualifiedName {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.browseName
}

// DisplayName returns the node's display name.
func (n *Node) DisplayName() *ua.LocalizedText {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.displayName
}

// AddressSpace holds the nodes of all namespaces.
type AddressSpace struct {
	mu         sync.RWMutex
	nodes      map[string]*Node
	namespaces []string

	subMu    sync.Mutex
	subCache map[[2]string]bool
}

func newAddressSpace() *AddressSpace {
	return &AddressSpace{
		nodes:      make(map[string]*Node, 8192),
		namespaces: []string{"http://opcfoundation.org/UA/"},
		subCache:   make(map[[2]string]bool),
	}
}

// key is the map key of a node id: cheap to build for the numeric and
// string ids that make up nearly all nodes.
func key(id *ua.NodeID) string {
	if id == nil {
		return ""
	}
	switch {
	case numericID(id):
		return strconv.FormatUint(uint64(id.Namespace()), 10) + ":i" + strconv.FormatUint(uint64(id.IntID()), 10)
	case id.Type() == ua.NodeIDTypeString:
		return strconv.FormatUint(uint64(id.Namespace()), 10) + ":s" + id.StringID()
	}
	return id.String()
}

// Node returns the node with the given id, or nil.
func (s *AddressSpace) Node(id *ua.NodeID) *Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nodes[key(id)]
}

// NamespaceArray returns the namespace URIs; the index is the namespace
// index.
func (s *AddressSpace) NamespaceArray() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.namespaces...)
}

// namespaceIndex returns the index of uri, registering it if new.
func (s *AddressSpace) namespaceIndex(uri string) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.namespaces {
		if u == uri {
			return uint16(i)
		}
	}
	s.namespaces = append(s.namespaces, uri)
	return uint16(len(s.namespaces) - 1)
}

// add inserts n. It fails with Bad_NodeIdExists for a duplicate id.
func (s *AddressSpace) add(n *Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(n.id)
	if _, ok := s.nodes[k]; ok {
		return ua.StatusBadNodeIDExists
	}
	s.nodes[k] = n
	if n.class == ua.NodeClassReferenceType || n.class == ua.NodeClassDataType ||
		n.class == ua.NodeClassObjectType || n.class == ua.NodeClassVariableType {
		s.resetSubtypes()
	}
	return nil
}

// addRef adds a reference and its inverse on the target.
func (s *AddressSpace) addRef(source, refType, target *ua.NodeID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addRefLocked(source, refType, target)
}

func (s *AddressSpace) addRefLocked(source, refType, target *ua.NodeID) {
	if src := s.nodes[key(source)]; src != nil && !hasRef(src.refs, refType, target, true) {
		src.refs = append(src.refs, reference{refType: refType, target: target, forward: true})
	}
	if tgt := s.nodes[key(target)]; tgt != nil && !hasRef(tgt.refs, refType, source, false) {
		tgt.refs = append(tgt.refs, reference{refType: refType, target: source, forward: false})
	}
	if refType.Namespace() == 0 && refType.IntID() == id.HasSubtype {
		s.resetSubtypes()
	}
}

func hasRef(refs []reference, refType, target *ua.NodeID, forward bool) bool {
	for _, r := range refs {
		if r.forward == forward && sameID(r.refType, refType) && sameID(r.target, target) {
			return true
		}
	}
	return false
}

// remove deletes the node and, recursively, the nodes it owns through
// forward HasComponent, HasProperty and Organizes references in a non-zero
// namespace, unless another node also references them. It returns the
// removed nodes.
func (s *AddressSpace) remove(nodeID *ua.NodeID) []*Node {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed []*Node
	var walk func(id *ua.NodeID)
	walk = func(id *ua.NodeID) {
		n := s.nodes[key(id)]
		if n == nil {
			return
		}
		delete(s.nodes, key(id))
		removed = append(removed, n)
		for _, r := range n.refs {
			// Drop the reverse side of every reference.
			if t := s.nodes[key(r.target)]; t != nil {
				t.refs = dropRefs(t.refs, n.id)
			}
		}
		for _, r := range n.refs {
			if !r.forward || r.target.Namespace() == 0 || !isOwning(r.refType) {
				continue
			}
			child := s.nodes[key(r.target)]
			if child != nil && !hasInverseOwner(child.refs) {
				walk(r.target)
			}
		}
	}
	walk(nodeID)
	return removed
}

func isOwning(refType *ua.NodeID) bool {
	if refType.Namespace() != 0 {
		return false
	}
	switch refType.IntID() {
	case id.HasComponent, id.HasProperty, id.Organizes, id.HasOrderedComponent:
		return true
	}
	return false
}

func hasInverseOwner(refs []reference) bool {
	for _, r := range refs {
		if !r.forward && isOwning(r.refType) {
			return true
		}
	}
	return false
}

func dropRefs(refs []reference, target *ua.NodeID) []reference {
	out := refs[:0]
	for _, r := range refs {
		if !sameID(r.target, target) {
			out = append(out, r)
		}
	}
	return out
}

// refsOf returns a copy of a node's references.
func (s *AddressSpace) refsOf(n *Node) []reference {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]reference(nil), n.refs...)
}

func (s *AddressSpace) resetSubtypes() {
	s.subMu.Lock()
	s.subCache = make(map[[2]string]bool)
	s.subMu.Unlock()
}

// isSubtype reports whether t is base or a subtype of base, following
// inverse HasSubtype references.
func (s *AddressSpace) isSubtype(t, base *ua.NodeID) bool {
	if t == nil || base == nil {
		return false
	}
	if sameID(t, base) {
		return true
	}
	ck := [2]string{key(t), key(base)}
	s.subMu.Lock()
	v, ok := s.subCache[ck]
	s.subMu.Unlock()
	if ok {
		return v
	}

	s.mu.RLock()
	res := false
	seen := map[string]bool{}
	cur := t
	for depth := 0; cur != nil && depth < 64 && !res; depth++ {
		n := s.nodes[key(cur)]
		if n == nil || seen[key(cur)] {
			break
		}
		seen[key(cur)] = true
		var parent *ua.NodeID
		for _, r := range n.refs {
			if !r.forward && r.refType.Namespace() == 0 && r.refType.IntID() == id.HasSubtype {
				parent = r.target
				break
			}
		}
		if parent != nil && sameID(parent, base) {
			res = true
		}
		cur = parent
	}
	s.mu.RUnlock()

	s.subMu.Lock()
	s.subCache[ck] = res
	s.subMu.Unlock()
	return res
}

// typeDefinition returns the target of the node's HasTypeDefinition.
func (s *AddressSpace) typeDefinition(n *Node) *ua.NodeID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range n.refs {
		if r.forward && r.refType.Namespace() == 0 && r.refType.IntID() == id.HasTypeDefinition {
			return r.target
		}
	}
	return nil
}

// child returns the target of a forward hierarchical reference from n
// whose browse name is name.
func (s *AddressSpace) child(n *Node, name *ua.QualifiedName) *Node {
	hier := ua.NewNumericNodeID(0, id.HierarchicalReferences)
	for _, r := range s.refsOf(n) {
		if !r.forward || !s.isSubtype(r.refType, hier) {
			continue
		}
		t := s.Node(r.target)
		if t == nil {
			continue
		}
		bn := t.BrowseName()
		if bn != nil && bn.NamespaceIndex == name.NamespaceIndex && bn.Name == name.Name {
			return t
		}
	}
	return nil
}

// dataValue returns a copy of the stored value or the result of the value
// function.
func (n *Node) dataValue() *ua.DataValue {
	n.mu.RLock()
	f := n.valueFunc
	v := n.value
	n.mu.RUnlock()
	if f != nil {
		if dv := f(); dv != nil {
			return dv
		}
		return &ua.DataValue{Value: nullVariant(), Status: ua.StatusBadWaitingForInitialData}
	}
	if v == nil {
		return &ua.DataValue{Value: nullVariant(), ServerTimestamp: time.Now()}
	}
	c := *v
	return &c
}

func nullVariant() *ua.Variant {
	v, _ := ua.NewVariant(nil)
	return v
}

// numericID reports whether n is a numeric id in any of its encodings.
func numericID(n *ua.NodeID) bool {
	switch n.Type() {
	case ua.NodeIDTypeTwoByte, ua.NodeIDTypeFourByte, ua.NodeIDTypeNumeric:
		return true
	}
	return false
}

// sameID compares node ids without formatting them, which NodeID.Equal
// does on every call.
func sameID(a, b *ua.NodeID) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Namespace() != b.Namespace() {
		return false
	}
	an, bn := numericID(a), numericID(b)
	switch {
	case an && bn:
		return a.IntID() == b.IntID()
	case an != bn:
		return false
	case a.Type() == ua.NodeIDTypeString && b.Type() == ua.NodeIDTypeString:
		return a.StringID() == b.StringID()
	}
	return a.String() == b.String()
}
