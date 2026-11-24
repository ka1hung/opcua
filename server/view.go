package server

import (
	"context"
	"math"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// maxReferencesPerBrowse caps the references returned per node in one
// call when the client asks for no limit; the rest come by BrowseNext.
const maxReferencesPerBrowse = 1000

// Browse result mask bits (OPC 10000-4 §5.9.2).
const (
	resultMaskReferenceType = 1 << iota
	resultMaskIsForward
	resultMaskNodeClass
	resultMaskBrowseName
	resultMaskDisplayName
	resultMaskTypeDefinition
)

type browseCP struct {
	refs []*ua.ReferenceDescription
	max  int
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.2
func (s *Server) browse(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.BrowseRequest)
	if err := s.checkOperations(len(req.NodesToBrowse)); err != nil {
		return nil, err
	}
	if req.View != nil && req.View.ViewID != nil && !isNull(req.View.ViewID) {
		return nil, ua.StatusBadViewIDUnknown
	}
	max := int(req.RequestedMaxReferencesPerNode)
	if max == 0 || max > maxReferencesPerBrowse {
		max = maxReferencesPerBrowse
	}
	results := make([]*ua.BrowseResult, len(req.NodesToBrowse))
	for i, bd := range req.NodesToBrowse {
		refs, st := s.browseNode(bd)
		if st != ua.StatusOK {
			results[i] = &ua.BrowseResult{StatusCode: st}
			continue
		}
		results[i] = s.page(r.Session, refs, max)
	}
	return &ua.BrowseResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func isNull(n *ua.NodeID) bool {
	return n == nil || n.Namespace() == 0 && n.Type() <= ua.NodeIDTypeNumeric && n.IntID() == 0
}

// page returns up to max references and keeps the rest behind a
// continuation point.
func (s *Server) page(sess *Session, refs []*ua.ReferenceDescription, max int) *ua.BrowseResult {
	if len(refs) <= max {
		return &ua.BrowseResult{StatusCode: ua.StatusOK, References: refs}
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if len(sess.browseCPs) >= s.cfg.limits.MaxBrowseContinuationPoints {
		return &ua.BrowseResult{StatusCode: ua.StatusBadNoContinuationPoints}
	}
	cp := randomBytes(16)
	sess.browseCPs[string(cp)] = &browseCP{refs: refs[max:], max: max}
	return &ua.BrowseResult{StatusCode: ua.StatusOK, ContinuationPoint: cp, References: refs[:max]}
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.3
func (s *Server) browseNext(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.BrowseNextRequest)
	if err := s.checkOperations(len(req.ContinuationPoints)); err != nil {
		return nil, err
	}
	sess := r.Session
	results := make([]*ua.BrowseResult, len(req.ContinuationPoints))
	for i, cp := range req.ContinuationPoints {
		sess.mu.Lock()
		state, ok := sess.browseCPs[string(cp)]
		delete(sess.browseCPs, string(cp))
		sess.mu.Unlock()
		switch {
		case !ok:
			results[i] = &ua.BrowseResult{StatusCode: ua.StatusBadContinuationPointInvalid}
		case req.ReleaseContinuationPoints:
			results[i] = &ua.BrowseResult{StatusCode: ua.StatusOK}
		default:
			results[i] = s.page(sess, state.refs, state.max)
		}
	}
	return &ua.BrowseNextResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

// browseNode lists the references of one node that match a description.
func (s *Server) browseNode(bd *ua.BrowseDescription) ([]*ua.ReferenceDescription, ua.StatusCode) {
	if bd == nil || bd.NodeID == nil {
		return nil, ua.StatusBadNodeIDInvalid
	}
	n := s.space.Node(bd.NodeID)
	if n == nil {
		return nil, ua.StatusBadNodeIDUnknown
	}
	if bd.BrowseDirection > ua.BrowseDirectionBoth {
		return nil, ua.StatusBadBrowseDirectionInvalid
	}
	refType := bd.ReferenceTypeID
	if isNull(refType) {
		refType = nil
	} else if t := s.space.Node(refType); t == nil || t.class != ua.NodeClassReferenceType {
		return nil, ua.StatusBadReferenceTypeIDInvalid
	}

	var out []*ua.ReferenceDescription
	for _, ref := range s.space.refsOf(n) {
		if bd.BrowseDirection == ua.BrowseDirectionForward && !ref.forward ||
			bd.BrowseDirection == ua.BrowseDirectionInverse && ref.forward {
			continue
		}
		if refType != nil {
			if bd.IncludeSubtypes {
				if !s.space.isSubtype(ref.refType, refType) {
					continue
				}
			} else if !sameID(ref.refType, refType) {
				continue
			}
		}
		t := s.space.Node(ref.target)
		if t == nil {
			continue
		}
		if bd.NodeClassMask != 0 && bd.NodeClassMask&uint32(t.class) == 0 {
			continue
		}
		out = append(out, s.describe(ref, t, bd.ResultMask))
	}
	return out, ua.StatusOK
}

func (s *Server) describe(ref reference, t *Node, mask uint32) *ua.ReferenceDescription {
	d := &ua.ReferenceDescription{
		NodeID:          ua.NewExpandedNodeID(t.id, "", 0),
		ReferenceTypeID: ua.NewTwoByteNodeID(0),
		BrowseName:      &ua.QualifiedName{},
		DisplayName:     ua.NewLocalizedText(""),
		TypeDefinition:  ua.NewExpandedNodeID(ua.NewTwoByteNodeID(0), "", 0),
	}
	if mask&resultMaskReferenceType != 0 {
		d.ReferenceTypeID = ref.refType
	}
	if mask&resultMaskIsForward != 0 {
		d.IsForward = ref.forward
	}
	if mask&resultMaskNodeClass != 0 {
		d.NodeClass = t.class
	}
	if mask&resultMaskBrowseName != 0 {
		d.BrowseName = t.BrowseName()
	}
	if mask&resultMaskDisplayName != 0 {
		d.DisplayName = orEmpty(t.DisplayName())
	}
	if mask&resultMaskTypeDefinition != 0 && (t.class == ua.NodeClassObject || t.class == ua.NodeClassVariable) {
		if td := s.space.typeDefinition(t); td != nil {
			d.TypeDefinition = ua.NewExpandedNodeID(td, "", 0)
		}
	}
	return d
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.4
func (s *Server) translateBrowsePaths(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.TranslateBrowsePathsToNodeIDsRequest)
	if err := s.checkOperations(len(req.BrowsePaths)); err != nil {
		return nil, err
	}
	results := make([]*ua.BrowsePathResult, len(req.BrowsePaths))
	for i, p := range req.BrowsePaths {
		results[i] = s.translatePath(p)
	}
	return &ua.TranslateBrowsePathsToNodeIDsResponse{ResponseHeader: okHeader(req), Results: results}, nil
}

func (s *Server) translatePath(p *ua.BrowsePath) *ua.BrowsePathResult {
	if p == nil || p.StartingNode == nil {
		return &ua.BrowsePathResult{StatusCode: ua.StatusBadNodeIDInvalid}
	}
	start := s.space.Node(p.StartingNode)
	if start == nil {
		return &ua.BrowsePathResult{StatusCode: ua.StatusBadNodeIDUnknown}
	}
	if p.RelativePath == nil || len(p.RelativePath.Elements) == 0 {
		return &ua.BrowsePathResult{StatusCode: ua.StatusBadNothingToDo}
	}
	hier := ua.NewNumericNodeID(0, id.HierarchicalReferences)
	current := []*Node{start}
	for _, el := range p.RelativePath.Elements {
		if el == nil || el.TargetName == nil || el.TargetName.Name == "" {
			return &ua.BrowsePathResult{StatusCode: ua.StatusBadBrowseNameInvalid}
		}
		refType := el.ReferenceTypeID
		includeSub := el.IncludeSubtypes
		if isNull(refType) {
			refType, includeSub = hier, true
		}
		var next []*Node
		seen := map[string]bool{}
		for _, n := range current {
			for _, ref := range s.space.refsOf(n) {
				if ref.forward == el.IsInverse {
					continue
				}
				if includeSub && !s.space.isSubtype(ref.refType, refType) || !includeSub && !sameID(ref.refType, refType) {
					continue
				}
				t := s.space.Node(ref.target)
				if t == nil || seen[key(t.id)] {
					continue
				}
				bn := t.BrowseName()
				if bn != nil && bn.NamespaceIndex == el.TargetName.NamespaceIndex && bn.Name == el.TargetName.Name {
					seen[key(t.id)] = true
					next = append(next, t)
				}
			}
		}
		if len(next) == 0 {
			return &ua.BrowsePathResult{StatusCode: ua.StatusBadNoMatch}
		}
		current = next
	}
	targets := make([]*ua.BrowsePathTarget, len(current))
	for i, n := range current {
		targets[i] = &ua.BrowsePathTarget{TargetID: ua.NewExpandedNodeID(n.id, "", 0), RemainingPathIndex: math.MaxUint32}
	}
	return &ua.BrowsePathResult{StatusCode: ua.StatusOK, Targets: targets}
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.5
func (s *Server) registerNodes(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.RegisterNodesRequest)
	if err := s.checkOperations(len(req.NodesToRegister)); err != nil {
		return nil, err
	}
	return &ua.RegisterNodesResponse{ResponseHeader: okHeader(req), RegisteredNodeIDs: req.NodesToRegister}, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.9.6
func (s *Server) unregisterNodes(ctx context.Context, r *Request) (ua.Response, error) {
	req := r.Body.(*ua.UnregisterNodesRequest)
	if err := s.checkOperations(len(req.NodesToUnregister)); err != nil {
		return nil, err
	}
	return &ua.UnregisterNodesResponse{ResponseHeader: okHeader(req)}, nil
}
