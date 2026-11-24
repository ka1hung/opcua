package server

import (
	"time"

	"github.com/ka1hung/opcua/id"
	"github.com/ka1hung/opcua/ua"
)

// initServerObject gives the variables of the Server object (OPC 10000-5
// §6.3.1) their values: some fixed, some computed when read.
func (s *Server) initServerObject() {
	dyn := func(nid uint32, f func() any) {
		n := s.space.Node(ua.NewNumericNodeID(0, nid))
		if n == nil {
			return
		}
		n.mu.Lock()
		n.valueFunc = func() *ua.DataValue {
			v, err := ua.NewVariant(f())
			if err != nil {
				return &ua.DataValue{Value: nullVariant(), Status: ua.StatusBadInternalError}
			}
			now := time.Now()
			return &ua.DataValue{Value: v, SourceTimestamp: now, ServerTimestamp: now}
		}
		n.mu.Unlock()
	}
	fixed := func(nid uint32, v any) { dyn(nid, func() any { return v }) }

	status := func() *ua.ServerStatusDataType {
		s.mu.Lock()
		state, start := s.state, s.startTime
		s.mu.Unlock()
		return &ua.ServerStatusDataType{
			StartTime:   start,
			CurrentTime: time.Now(),
			State:       state,
			BuildInfo: &ua.BuildInfo{
				ProductURI:       s.cfg.productURI,
				ManufacturerName: s.cfg.manufacturerName,
				ProductName:      s.cfg.productName,
				SoftwareVersion:  s.cfg.softwareVersion,
			},
			ShutdownReason: ua.NewLocalizedText(""),
		}
	}

	dyn(id.Server_ServerStatus, func() any { return ua.NewExtensionObject(status()) })
	dyn(id.Server_ServerStatus_StartTime, func() any { return status().StartTime })
	dyn(id.Server_ServerStatus_CurrentTime, func() any { return time.Now() })
	dyn(id.Server_ServerStatus_State, func() any { return int32(status().State) })
	dyn(id.Server_ServerStatus_BuildInfo, func() any { return ua.NewExtensionObject(status().BuildInfo) })
	fixed(id.Server_ServerStatus_BuildInfo_ProductURI, s.cfg.productURI)
	fixed(id.Server_ServerStatus_BuildInfo_ManufacturerName, s.cfg.manufacturerName)
	fixed(id.Server_ServerStatus_BuildInfo_ProductName, s.cfg.productName)
	fixed(id.Server_ServerStatus_BuildInfo_SoftwareVersion, s.cfg.softwareVersion)
	fixed(id.Server_ServerStatus_BuildInfo_BuildNumber, "")
	fixed(id.Server_ServerStatus_BuildInfo_BuildDate, time.Time{})
	fixed(id.Server_ServerStatus_SecondsTillShutdown, uint32(0))
	dyn(id.Server_ServerStatus_ShutdownReason, func() any { return ua.NewLocalizedText("") })

	dyn(id.Server_NamespaceArray, func() any { return s.space.NamespaceArray() })
	dyn(id.Server_ServerArray, func() any { return []string{s.cfg.applicationURI} })
	fixed(id.Server_ServiceLevel, uint8(255))
	fixed(id.Server_Auditing, false)
	fixed(id.Server_ServerDiagnostics_EnabledFlag, false)

	lim := s.cfg.limits
	maxNodes := uint32(lim.MaxNodesPerRequest)
	fixed(id.Server_ServerCapabilities_ServerProfileArray, []string{
		"http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice",
	})
	fixed(id.Server_ServerCapabilities_LocaleIDArray, []string{"en"})
	fixed(id.Server_ServerCapabilities_MinSupportedSampleRate, float64(lim.MinSamplingInterval/time.Millisecond))
	fixed(id.Server_ServerCapabilities_MaxBrowseContinuationPoints, uint16(lim.MaxBrowseContinuationPoints))
	fixed(id.Server_ServerCapabilities_MaxQueryContinuationPoints, uint16(0))
	fixed(id.Server_ServerCapabilities_MaxHistoryContinuationPoints, uint16(lim.MaxBrowseContinuationPoints))
	fixed(id.Server_ServerCapabilities_MaxArrayLength, uint32(0))
	fixed(id.Server_ServerCapabilities_MaxStringLength, uint32(0))
	fixed(id.Server_ServerCapabilities_MaxByteStringLength, uint32(0))
	for _, nid := range []uint32{
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRead,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadData,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryReadEvents,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerWrite,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerMethodCall,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerBrowse,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerRegisterNodes,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerTranslateBrowsePathsToNodeIDs,
		id.Server_ServerCapabilities_OperationLimits_MaxMonitoredItemsPerCall,
	} {
		fixed(nid, maxNodes)
	}
	for _, nid := range []uint32{
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateData,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerHistoryUpdateEvents,
		id.Server_ServerCapabilities_OperationLimits_MaxNodesPerNodeManagement,
	} {
		fixed(nid, uint32(0))
	}

	// History capabilities (OPC 10000-11 §5.4.2) and the aggregates of
	// processed reads (OPC 10000-13 §4.2.2).
	hasHistory := func() any { return s.historyReader() != nil }
	dyn(id.HistoryServerCapabilities_AccessHistoryDataCapability, hasHistory)
	dyn(id.HistoryServerCapabilities_AccessHistoryEventsCapability, hasHistory)
	fixed(id.HistoryServerCapabilities_MaxReturnDataValues, uint32(maxHistoryValues))
	fixed(id.HistoryServerCapabilities_MaxReturnEventValues, uint32(maxHistoryValues))
	for _, nid := range []uint32{
		id.HistoryServerCapabilities_InsertDataCapability,
		id.HistoryServerCapabilities_ReplaceDataCapability,
		id.HistoryServerCapabilities_UpdateDataCapability,
		id.HistoryServerCapabilities_DeleteRawCapability,
		id.HistoryServerCapabilities_DeleteAtTimeCapability,
		id.HistoryServerCapabilities_InsertEventCapability,
		id.HistoryServerCapabilities_ReplaceEventCapability,
		id.HistoryServerCapabilities_UpdateEventCapability,
		id.HistoryServerCapabilities_DeleteEventCapability,
		id.HistoryServerCapabilities_InsertAnnotationCapability,
	} {
		fixed(nid, false)
	}
	fixed(id.HistoryServerCapabilities_ServerTimestampSupported, true)
	organizes := ua.NewNumericNodeID(0, id.Organizes)
	for _, agg := range aggregateIDs {
		for _, folder := range []uint32{id.Server_ServerCapabilities_AggregateFunctions, id.HistoryServerCapabilities_AggregateFunctions} {
			s.space.addRef(ua.NewNumericNodeID(0, folder), organizes, ua.NewNumericNodeID(0, agg))
		}
	}

	// The Server object is the root notifier of all events.
	if n := s.space.Node(ua.NewNumericNodeID(0, id.Server)); n != nil {
		n.mu.Lock()
		n.eventNotifier |= EventNotifierSubscribeToEvents
		n.mu.Unlock()
	}
}
