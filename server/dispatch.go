package server

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
	"github.com/ka1hung/opcua/uasc"
)

// Request is one service request as a handler sees it.
type Request struct {
	// SC is the secure channel the request came on.
	SC *uasc.SecureChannel
	// Session is the request's session; nil for services that need none.
	Session *Session
	// ID is the request id, to send a response later.
	ID uint32
	// Body is the request.
	Body ua.Request
}

// Handler handles one service. It returns the response, or an error that
// becomes a ServiceFault (a ua.StatusCode, or Bad_UnexpectedError). A
// handler that answers later, as Publish does, returns nil, nil.
type Handler func(ctx context.Context, r *Request) (ua.Response, error)

type sessionNeed int

const (
	needNone      sessionNeed = iota // discovery, CreateSession
	needAny                          // ActivateSession: checked by the handler
	needBound                        // CloseSession: on this channel, maybe not activated
	needActivated                    // everything else
)

var noSessionServices = map[uint16]bool{
	id.FindServersRequest_Encoding_DefaultBinary:          true,
	id.FindServersOnNetworkRequest_Encoding_DefaultBinary: true,
	id.GetEndpointsRequest_Encoding_DefaultBinary:         true,
	id.RegisterServerRequest_Encoding_DefaultBinary:       true,
	id.RegisterServer2Request_Encoding_DefaultBinary:      true,
	id.CreateSessionRequest_Encoding_DefaultBinary:        true,
}

func sessionNeedOf(typeID uint16) sessionNeed {
	switch {
	case noSessionServices[typeID]:
		return needNone
	case typeID == id.ActivateSessionRequest_Encoding_DefaultBinary:
		return needAny
	case typeID == id.CloseSessionRequest_Encoding_DefaultBinary:
		return needBound
	}
	return needActivated
}

// isDiscoveryService reports whether typeID is a discovery service request,
// which a client may call on an unsecured channel.
func isDiscoveryService(typeID uint16) bool {
	switch typeID {
	case id.FindServersRequest_Encoding_DefaultBinary,
		id.FindServersOnNetworkRequest_Encoding_DefaultBinary,
		id.GetEndpointsRequest_Encoding_DefaultBinary:
		return true
	}
	return false
}

// RegisterHandler sets the handler of a service, replacing the built-in
// one. typeID is the request's binary encoding id. Call before Start.
func (s *Server) RegisterHandler(typeID uint16, h Handler) {
	s.handlers[typeID] = h
}

func (s *Server) handleService(ctx context.Context, sc *uasc.SecureChannel, reqID uint32, req ua.Request) {
	typeID := ua.ServiceTypeID(req)
	var handle uint32
	var token *ua.NodeID
	if hdr := req.Header(); hdr != nil {
		handle = hdr.RequestHandle
		token = hdr.AuthenticationToken
	}

	resp, err := s.dispatch(ctx, sc, reqID, req, typeID, token)
	if err != nil {
		status, ok := err.(ua.StatusCode)
		if !ok {
			s.logError("%T: %s", req, err)
			status = ua.StatusBadUnexpectedError
		}
		resp = &ua.ServiceFault{ResponseHeader: responseHeader(handle, status)}
	}
	if resp == nil {
		return // answered later
	}
	if err := sc.SendResponseWithContext(ctx, reqID, resp); err != nil {
		s.logDebug("sending %T: %s", resp, err)
	}
}

func (s *Server) dispatch(ctx context.Context, sc *uasc.SecureChannel, reqID uint32, req ua.Request, typeID uint16, token *ua.NodeID) (resp ua.Response, err error) {
	h, ok := s.handlers[typeID]
	if !ok {
		return nil, ua.StatusBadServiceUnsupported
	}
	if s.discoveryOnly(sc) && !isDiscoveryService(typeID) {
		// A None channel on a server that does not offer None for sessions
		// may only be used for discovery.
		return nil, ua.StatusBadSecurityPolicyRejected
	}

	r := &Request{SC: sc, ID: reqID, Body: req}
	switch sessionNeedOf(typeID) {
	case needNone:
	case needAny:
		if r.Session = s.sessions.byAuthToken(token); r.Session == nil {
			return nil, ua.StatusBadSessionIDInvalid
		}
	default:
		sess := s.sessions.byAuthToken(token)
		if sess == nil {
			return nil, ua.StatusBadSessionIDInvalid
		}
		sess.mu.Lock()
		bound := sess.channelID == sc.SecureChannelID()
		activated := sess.activated
		sess.mu.Unlock()
		if !bound {
			// A session is used only on the channel it was activated on
			// (OPC 10000-4 §5.6.3).
			return nil, ua.StatusBadSecureChannelIDInvalid
		}
		if !activated && sessionNeedOf(typeID) == needActivated {
			return nil, ua.StatusBadSessionNotActivated
		}
		r.Session = sess
	}
	if r.Session != nil {
		r.Session.touch()
	}

	defer func() {
		if p := recover(); p != nil {
			s.logError("panic in handler for %T: %v\n%s", req, p, debug.Stack())
			resp, err = nil, ua.StatusBadInternalError
		}
	}()
	return h(withSession(ctx, r.Session), r)
}

func responseHeader(handle uint32, status ua.StatusCode) *ua.ResponseHeader {
	return &ua.ResponseHeader{
		Timestamp:          time.Now(),
		RequestHandle:      handle,
		ServiceResult:      status,
		ServiceDiagnostics: &ua.DiagnosticInfo{},
		StringTable:        []string{},
		AdditionalHeader:   ua.NewExtensionObject(nil),
	}
}

func okHeader(req ua.Request) *ua.ResponseHeader {
	var handle uint32
	if h := req.Header(); h != nil {
		handle = h.RequestHandle
	}
	return responseHeader(handle, ua.StatusOK)
}

// checkOperations enforces the per-request operation limit (OPC 10000-4
// §5.5: Bad_NothingToDo, Bad_TooManyOperations).
func (s *Server) checkOperations(n int) error {
	if n == 0 {
		return ua.StatusBadNothingToDo
	}
	if n > s.cfg.limits.MaxNodesPerRequest {
		return ua.StatusBadTooManyOperations
	}
	return nil
}

func (s *Server) initHandlers() {
	reg := func(typeID uint16, h Handler) {
		if _, ok := s.handlers[typeID]; !ok {
			s.handlers[typeID] = h
		}
	}
	// Discovery
	reg(id.FindServersRequest_Encoding_DefaultBinary, s.findServers)
	reg(id.GetEndpointsRequest_Encoding_DefaultBinary, s.getEndpoints)
	// Session
	reg(id.CreateSessionRequest_Encoding_DefaultBinary, s.createSession)
	reg(id.ActivateSessionRequest_Encoding_DefaultBinary, s.activateSession)
	reg(id.CloseSessionRequest_Encoding_DefaultBinary, s.closeSession)
	reg(id.CancelRequest_Encoding_DefaultBinary, s.cancelRequest)
	// View
	reg(id.BrowseRequest_Encoding_DefaultBinary, s.browse)
	reg(id.BrowseNextRequest_Encoding_DefaultBinary, s.browseNext)
	reg(id.TranslateBrowsePathsToNodeIDsRequest_Encoding_DefaultBinary, s.translateBrowsePaths)
	reg(id.RegisterNodesRequest_Encoding_DefaultBinary, s.registerNodes)
	reg(id.UnregisterNodesRequest_Encoding_DefaultBinary, s.unregisterNodes)
	// Attribute
	reg(id.ReadRequest_Encoding_DefaultBinary, s.read)
	reg(id.WriteRequest_Encoding_DefaultBinary, s.write)
	// Subscription and MonitoredItem
	reg(id.CreateSubscriptionRequest_Encoding_DefaultBinary, s.createSubscription)
	reg(id.ModifySubscriptionRequest_Encoding_DefaultBinary, s.modifySubscription)
	reg(id.SetPublishingModeRequest_Encoding_DefaultBinary, s.setPublishingMode)
	reg(id.PublishRequest_Encoding_DefaultBinary, s.publish)
	reg(id.RepublishRequest_Encoding_DefaultBinary, s.republish)
	reg(id.TransferSubscriptionsRequest_Encoding_DefaultBinary, s.transferSubscriptions)
	reg(id.DeleteSubscriptionsRequest_Encoding_DefaultBinary, s.deleteSubscriptions)
	reg(id.CreateMonitoredItemsRequest_Encoding_DefaultBinary, s.createMonitoredItems)
	reg(id.ModifyMonitoredItemsRequest_Encoding_DefaultBinary, s.modifyMonitoredItems)
	reg(id.SetMonitoringModeRequest_Encoding_DefaultBinary, s.setMonitoringMode)
	reg(id.DeleteMonitoredItemsRequest_Encoding_DefaultBinary, s.deleteMonitoredItems)
	s.initMoreHandlers(reg)
}
