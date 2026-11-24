package uatest2

import (
	"context"
	"log"

	"github.com/ka1hung/opcua/server"
	"github.com/ka1hung/opcua/ua"
)

// startServer starts the in-tree server on opc.tcp://localhost:4840 with
// the variables the tests in this package read and write, in namespace 1.
func startServer() *server.Server {
	s := server.New(
		server.EnableSecurity("None", ua.MessageSecurityModeNone),
		server.EnableAuthMode(ua.UserTokenTypeAnonymous),
		server.AnonymousReadOnly(false),
		server.EndPoint("localhost", 4840),
	)

	s.AddNamespace("NodeNamespace")
	s.AddNamespace("http://gopcua.com/")

	no := func(*server.Identity) bool { return false }
	add := func(name string, value any, spec server.VariableSpec) {
		spec.NodeID = ua.NewStringNodeID(1, name)
		spec.BrowseName = name
		spec.Value = value
		if _, err := s.AddVariable(server.ObjectsFolder, spec); err != nil {
			log.Fatalf("add %s: %s", name, err)
		}
	}
	add("ro_bool", true, server.VariableSpec{DataType: ua.TypeIDBoolean, Writable: true, CanWrite: no})
	add("rw_bool", true, server.VariableSpec{DataType: ua.TypeIDBoolean, Writable: true})
	add("ro_int32", int32(5), server.VariableSpec{DataType: ua.TypeIDInt32, Writable: true, CanWrite: no})
	add("rw_int32", int32(5), server.VariableSpec{DataType: ua.TypeIDInt32, Writable: true})
	add("NoPermVariable", int32(742), server.VariableSpec{DataType: ua.TypeIDInt32})
	add("ReadWriteVariable", 12.34, server.VariableSpec{DataType: ua.TypeIDDouble, Writable: true})
	add("ReadOnlyVariable", 9.87, server.VariableSpec{DataType: ua.TypeIDDouble})
	add("NoAccessVariable", 55.43, server.VariableSpec{DataType: ua.TypeIDDouble, CanRead: no})

	if err := s.Start(context.Background()); err != nil {
		log.Fatalf("Error starting server, exiting: %s", err)
	}
	return s
}
