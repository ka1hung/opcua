package server

import (
	"fmt"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// ObjectsFolder is the id of the standard Objects folder, the usual parent
// of an application's nodes.
var ObjectsFolder = ua.NewNumericNodeID(0, id.ObjectsFolder)

var (
	refOrganizes         = ua.NewNumericNodeID(0, id.Organizes)
	refHasComponent      = ua.NewNumericNodeID(0, id.HasComponent)
	refHasProperty       = ua.NewNumericNodeID(0, id.HasProperty)
	refHasTypeDefinition = ua.NewNumericNodeID(0, id.HasTypeDefinition)
	refHasNotifier       = ua.NewNumericNodeID(0, id.HasNotifier)
	refHasEventSource    = ua.NewNumericNodeID(0, id.HasEventSource)
	typeFolder           = ua.NewNumericNodeID(0, id.FolderType)
	typeBaseObject       = ua.NewNumericNodeID(0, id.BaseObjectType)
	typeBaseDataVariable = ua.NewNumericNodeID(0, id.BaseDataVariableType)
	typeAnalogItem       = ua.NewNumericNodeID(0, id.AnalogItemType)
	typeProperty         = ua.NewNumericNodeID(0, id.PropertyType)
)

// AddNamespace registers a namespace URI and returns its index. The
// server's own namespace is 1, so the first namespace an application adds
// is 2; namespaces added in the same order keep their indices.
func (s *Server) AddNamespace(uri string) uint16 {
	return s.space.namespaceIndex(uri)
}

// ObjectSpec describes an Object node.
type ObjectSpec struct {
	NodeID      *ua.NodeID
	BrowseName  string
	DisplayName string // defaults to BrowseName
	Description string
	// TypeDefinition defaults to BaseObjectType.
	TypeDefinition *ua.NodeID
	// EventNotifier makes the object a source of events that clients can
	// subscribe to.
	EventNotifier bool
	// EventHistory lets clients read the object's past events from the
	// HistoryReader.
	EventHistory bool
}

// AddFolder adds a folder below parent.
func (s *Server) AddFolder(parent, nodeID *ua.NodeID, name string) (*Node, error) {
	return s.AddObject(parent, ObjectSpec{NodeID: nodeID, BrowseName: name, TypeDefinition: typeFolder})
}

// AddObject adds an Object node below parent.
func (s *Server) AddObject(parent *ua.NodeID, spec ObjectSpec) (*Node, error) {
	if spec.NodeID == nil || spec.BrowseName == "" {
		return nil, fmt.Errorf("server: object needs NodeID and BrowseName")
	}
	p := s.space.Node(parent)
	if p == nil {
		return nil, fmt.Errorf("server: parent %s: %w", parent, ua.StatusBadParentNodeIDInvalid)
	}
	td := spec.TypeDefinition
	if td == nil {
		td = typeBaseObject
	}
	n := &Node{
		id:          spec.NodeID,
		class:       ua.NodeClassObject,
		browseName:  &ua.QualifiedName{NamespaceIndex: spec.NodeID.Namespace(), Name: spec.BrowseName},
		displayName: ua.NewLocalizedText(orDefault(spec.DisplayName, spec.BrowseName)),
		description: ua.NewLocalizedText(spec.Description),
	}
	if spec.EventNotifier {
		n.eventNotifier = EventNotifierSubscribeToEvents
	}
	if spec.EventHistory {
		n.eventNotifier |= EventNotifierHistoryRead
	}
	if err := s.space.add(n); err != nil {
		return nil, fmt.Errorf("server: add %s: %w", spec.NodeID, err)
	}
	s.space.addRef(parent, s.childRef(p, n.class), n.id)
	s.space.addRef(n.id, refHasTypeDefinition, td)
	if spec.EventNotifier {
		// Events of this object reach the notifiers above it.
		s.space.addRef(s.notifierAbove(p), refHasNotifier, n.id)
	}
	return n, nil
}

// notifierAbove returns the nearest node at or above p that is an event
// notifier, or the Server object.
func (s *Server) notifierAbove(p *Node) *ua.NodeID {
	p.mu.RLock()
	en := p.eventNotifier
	p.mu.RUnlock()
	if en&EventNotifierSubscribeToEvents != 0 {
		return p.id
	}
	return ua.NewNumericNodeID(0, id.Server)
}

// childRef is the reference type from parent to a new child: Organizes
// below a folder, HasComponent otherwise.
func (s *Server) childRef(parent *Node, class ua.NodeClass) *ua.NodeID {
	if td := s.space.typeDefinition(parent); td != nil && s.space.isSubtype(td, typeFolder) {
		return refOrganizes
	}
	if sameID(parent.id, ObjectsFolder) || parent.class == ua.NodeClassView {
		return refOrganizes
	}
	return refHasComponent
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// VariableSpec describes a Variable node.
type VariableSpec struct {
	NodeID      *ua.NodeID
	BrowseName  string
	DisplayName string // defaults to BrowseName
	Description string

	// DataType is the variable's built-in type, e.g. ua.TypeIDDouble.
	// DataTypeID, if set, is used instead, for any DataType node.
	DataType   ua.TypeID
	DataTypeID *ua.NodeID
	// Array makes the value a one-dimensional array.
	Array bool

	// Writable lets clients write the value.
	Writable bool
	// Unit and EURange add the EngineeringUnits and EURange properties of
	// an AnalogItem. EURange is needed for percent deadband subscriptions.
	Unit    string
	EURange *Range
	// Historizing marks the variable as having history.
	Historizing bool
	// MinimumSamplingInterval in milliseconds; 0 means the value changes
	// only through SetValue and is reported on change.
	MinimumSamplingInterval float64

	// CanRead and CanWrite decide per user; nil allows everyone (subject
	// to AnonymousReadOnly).
	CanRead  func(*Identity) bool
	CanWrite func(*Identity) bool
	// OnWrite handles writes of this variable; it overrides Server.OnWrite.
	OnWrite WriteFunc

	// Value is the initial value; without it the variable reads
	// Bad_WaitingForInitialData until SetValue.
	Value any
}

// AddVariable adds a Variable node below parent.
func (s *Server) AddVariable(parent *ua.NodeID, spec VariableSpec) (*Node, error) {
	if spec.NodeID == nil || spec.BrowseName == "" {
		return nil, fmt.Errorf("server: variable needs NodeID and BrowseName")
	}
	p := s.space.Node(parent)
	if p == nil {
		return nil, fmt.Errorf("server: parent %s: %w", parent, ua.StatusBadParentNodeIDInvalid)
	}
	dt := spec.DataTypeID
	if dt == nil {
		if spec.DataType == 0 {
			dt = ua.NewNumericNodeID(0, id.BaseDataType)
		} else {
			dt = ua.NewNumericNodeID(0, uint32(spec.DataType))
		}
	}
	al := AccessLevelCurrentRead
	if spec.Writable {
		al |= AccessLevelCurrentWrite
	}
	if spec.Historizing {
		al |= AccessLevelHistoryRead
	}
	rank := int32(-1)
	if spec.Array {
		rank = 1
	}
	n := &Node{
		id:          spec.NodeID,
		class:       ua.NodeClassVariable,
		browseName:  &ua.QualifiedName{NamespaceIndex: spec.NodeID.Namespace(), Name: spec.BrowseName},
		displayName: ua.NewLocalizedText(orDefault(spec.DisplayName, spec.BrowseName)),
		description: ua.NewLocalizedText(spec.Description),
		dataType:    dt,
		valueRank:   rank,
		accessLevel: al,
		minSampling: spec.MinimumSamplingInterval,
		historizing: spec.Historizing,
		euRange:     spec.EURange,
		canRead:     spec.CanRead,
		canWrite:    spec.CanWrite,
		onWrite:     spec.OnWrite,
		value:       &ua.DataValue{Value: nullVariant(), Status: ua.StatusBadWaitingForInitialData, ServerTimestamp: time.Now()},
	}
	if spec.Value != nil {
		v, err := ua.NewVariant(spec.Value)
		if err != nil {
			return nil, fmt.Errorf("server: %s: initial value: %w", spec.NodeID, err)
		}
		now := time.Now()
		n.value = &ua.DataValue{Value: v, SourceTimestamp: now, ServerTimestamp: now}
	}
	if err := s.space.add(n); err != nil {
		return nil, fmt.Errorf("server: add %s: %w", spec.NodeID, err)
	}
	s.space.addRef(parent, s.childRef(p, n.class), n.id)
	td := typeBaseDataVariable
	if spec.Unit != "" || spec.EURange != nil {
		td = typeAnalogItem
	}
	s.space.addRef(n.id, refHasTypeDefinition, td)

	if spec.Unit != "" {
		eu := &ua.EUInformation{
			NamespaceURI: "http://www.opcfoundation.org/UA/units/un/cefact",
			UnitID:       -1,
			DisplayName:  ua.NewLocalizedText(spec.Unit),
			Description:  ua.NewLocalizedText(spec.Unit),
		}
		if err := s.addProperty(n, "EngineeringUnits", ua.NewNumericNodeID(0, id.EUInformation), ua.NewExtensionObject(eu)); err != nil {
			return nil, err
		}
	}
	if spec.EURange != nil {
		r := &ua.Range{Low: spec.EURange.Low, High: spec.EURange.High}
		if err := s.addProperty(n, "EURange", ua.NewNumericNodeID(0, id.Range), ua.NewExtensionObject(r)); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// addProperty adds a read-only property to a node. Its id is the parent's
// id with "." and the name appended, as a string id.
func (s *Server) addProperty(parent *Node, name string, dataType *ua.NodeID, value any) error {
	v, err := ua.NewVariant(value)
	if err != nil {
		return err
	}
	pid := ua.NewStringNodeID(parent.id.Namespace(), propertyIDBase(parent.id)+"."+name)
	now := time.Now()
	p := &Node{
		id:          pid,
		class:       ua.NodeClassVariable,
		browseName:  &ua.QualifiedName{NamespaceIndex: 0, Name: name},
		displayName: ua.NewLocalizedText(name),
		dataType:    dataType,
		valueRank:   -1,
		accessLevel: AccessLevelCurrentRead,
		value:       &ua.DataValue{Value: v, SourceTimestamp: now, ServerTimestamp: now},
	}
	if err := s.space.add(p); err != nil {
		return fmt.Errorf("server: add %s: %w", pid, err)
	}
	s.space.addRef(parent.id, refHasProperty, pid)
	s.space.addRef(pid, refHasTypeDefinition, typeProperty)
	return nil
}

func propertyIDBase(n *ua.NodeID) string {
	if n.Type() == ua.NodeIDTypeString {
		return n.StringID()
	}
	return n.String()
}

// SetValue sets a variable's value and reports it to subscribed clients if
// it changed. status is the quality (ua.StatusOK for Good); a zero
// sourceTime means now.
func (s *Server) SetValue(nodeID *ua.NodeID, value any, status ua.StatusCode, sourceTime time.Time) error {
	v, err := ua.NewVariant(value)
	if err != nil {
		return fmt.Errorf("server: %s: %w", nodeID, err)
	}
	now := time.Now()
	if sourceTime.IsZero() {
		sourceTime = now
	}
	return s.SetDataValue(nodeID, &ua.DataValue{Value: v, Status: status, SourceTimestamp: sourceTime, ServerTimestamp: now})
}

// SetDataValue sets a variable's value with its status and timestamps.
func (s *Server) SetDataValue(nodeID *ua.NodeID, dv *ua.DataValue) error {
	n := s.space.Node(nodeID)
	if n == nil || n.class != ua.NodeClassVariable {
		return fmt.Errorf("server: %s: %w", nodeID, ua.StatusBadNodeIDUnknown)
	}
	if dv.ServerTimestamp.IsZero() {
		dv.ServerTimestamp = time.Now()
	}
	if dv.Value == nil {
		dv.Value = nullVariant()
	}
	n.setValue(dv)
	return nil
}

// Value returns a variable's current value.
func (s *Server) Value(nodeID *ua.NodeID) (*ua.DataValue, error) {
	n := s.space.Node(nodeID)
	if n == nil {
		return nil, fmt.Errorf("server: %s: %w", nodeID, ua.StatusBadNodeIDUnknown)
	}
	return n.dataValue(), nil
}

// OnWrite sets the handler for writes of variables that have no OnWrite of
// their own. Without a handler, written values are stored as they are.
func (s *Server) OnWrite(f WriteFunc) {
	s.writeMu.Lock()
	s.onWrite = f
	s.writeMu.Unlock()
}

// RemoveNode removes a node and the nodes it owns (its components,
// properties and organized nodes that have no other parent). Clients
// monitoring a removed variable get Bad_NodeIdUnknown.
func (s *Server) RemoveNode(nodeID *ua.NodeID) error {
	if nodeID.Namespace() == 0 {
		return fmt.Errorf("server: %s: standard nodes cannot be removed", nodeID)
	}
	removed := s.space.remove(nodeID)
	if len(removed) == 0 {
		return fmt.Errorf("server: %s: %w", nodeID, ua.StatusBadNodeIDUnknown)
	}
	for _, n := range removed {
		nodeRemoved(n)
	}
	return nil
}

// Stats describes the server's current load.
type Stats struct {
	Connections   int
	Sessions      []SessionInfo
	Subscriptions int
}

// SessionInfo describes a session for display.
type SessionInfo struct {
	ID            string
	Name          string
	ClientURI     string
	User          string
	Activated     bool
	LastActivity  time.Time
	Subscriptions int
}

// Stats returns the current connections, sessions and subscriptions.
func (s *Server) Stats() Stats {
	st := Stats{Connections: s.cb.count(), Subscriptions: s.subs.count()}
	for _, sess := range s.sessions.list() {
		sess.mu.Lock()
		info := SessionInfo{
			ID:           sess.id.String(),
			Name:         sess.name,
			ClientURI:    sess.clientURI,
			Activated:    sess.activated,
			LastActivity: sess.lastActivity,
		}
		if sess.identity != nil && !sess.identity.Anonymous() {
			info.User = sess.identity.UserName
			if sess.identity.Certificate != nil {
				info.User = sess.identity.Certificate.Subject.CommonName
			}
		}
		sess.mu.Unlock()
		info.Subscriptions = len(s.subs.ofSession(sess))
		st.Sessions = append(st.Sessions, info)
	}
	return st
}
