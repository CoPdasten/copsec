package copsecproto

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
)

type LogEvent struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	NodeId           string                 `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
	Source           string                 `protobuf:"bytes,2,opt,name=source,proto3" json:"source,omitempty"`
	RawLine          string                 `protobuf:"bytes,3,opt,name=raw_line,json=rawLine,proto3" json:"raw_line,omitempty"`
	ClientIp         string                 `protobuf:"bytes,4,opt,name=client_ip,json=clientIp,proto3" json:"client_ip,omitempty"`
	StatusCode       int32                  `protobuf:"varint,5,opt,name=status_code,json=statusCode,proto3" json:"status_code,omitempty"`
	TimestampMs      int64                  `protobuf:"varint,6,opt,name=timestamp_ms,json=timestampMs,proto3" json:"timestamp_ms,omitempty"`
	RuleId           string                 `protobuf:"bytes,7,opt,name=rule_id,json=ruleId,proto3" json:"rule_id,omitempty"`
	MitreTechniqueId string                 `protobuf:"bytes,8,opt,name=mitre_technique_id,json=mitreTechniqueId,proto3" json:"mitre_technique_id,omitempty"`
	ThreatScore      int32                  `protobuf:"varint,9,opt,name=threat_score,json=threatScore,proto3" json:"threat_score,omitempty"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *LogEvent) Reset() {
	*x = LogEvent{}
	mi := &file_copsec_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *LogEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LogEvent) ProtoMessage() {}

func (x *LogEvent) ProtoReflect() protoreflect.Message {
	mi := &file_copsec_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *LogEvent) GetNodeId() string           { if x != nil { return x.NodeId }; return "" }
func (x *LogEvent) GetSource() string           { if x != nil { return x.Source }; return "" }
func (x *LogEvent) GetRawLine() string          { if x != nil { return x.RawLine }; return "" }
func (x *LogEvent) GetClientIp() string         { if x != nil { return x.ClientIp }; return "" }
func (x *LogEvent) GetStatusCode() int32        { if x != nil { return x.StatusCode }; return 0 }
func (x *LogEvent) GetTimestampMs() int64       { if x != nil { return x.TimestampMs }; return 0 }
func (x *LogEvent) GetRuleId() string           { if x != nil { return x.RuleId }; return "" }
func (x *LogEvent) GetMitreTechniqueId() string { if x != nil { return x.MitreTechniqueId }; return "" }
func (x *LogEvent) GetThreatScore() int32       { if x != nil { return x.ThreatScore }; return 0 }

type StreamAck struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	Success        bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	ProcessedCount uint64                 `protobuf:"varint,2,opt,name=processed_count,json=processedCount,proto3" json:"processed_count,omitempty"`
	Message        string                 `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *StreamAck) Reset() {
	*x = StreamAck{}
	mi := &file_copsec_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *StreamAck) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StreamAck) ProtoMessage() {}

func (x *StreamAck) ProtoReflect() protoreflect.Message {
	mi := &file_copsec_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *StreamAck) GetSuccess() bool           { if x != nil { return x.Success }; return false }
func (x *StreamAck) GetProcessedCount() uint64 { if x != nil { return x.ProcessedCount }; return 0 }
func (x *StreamAck) GetMessage() string         { if x != nil { return x.Message }; return "" }

type Heartbeat struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	NodeId          string                 `protobuf:"bytes,1,opt,name=node_id,json=nodeId,proto3" json:"node_id,omitempty"`
	UptimeSeconds   int64                  `protobuf:"varint,2,opt,name=uptime_seconds,json=uptimeSeconds,proto3" json:"uptime_seconds,omitempty"`
	CpuUsage        float64                `protobuf:"fixed64,3,opt,name=cpu_usage,json=cpuUsage,proto3" json:"cpu_usage,omitempty"`
	MemoryUsage     float64                `protobuf:"fixed64,4,opt,name=memory_usage,json=memoryUsage,proto3" json:"memory_usage,omitempty"`
	ActiveBansCount int32                  `protobuf:"varint,5,opt,name=active_bans_count,json=activeBansCount,proto3" json:"active_bans_count,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *Heartbeat) Reset() {
	*x = Heartbeat{}
	mi := &file_copsec_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Heartbeat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Heartbeat) ProtoMessage() {}

func (x *Heartbeat) ProtoReflect() protoreflect.Message {
	mi := &file_copsec_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *Heartbeat) GetNodeId() string          { if x != nil { return x.NodeId }; return "" }
func (x *Heartbeat) GetUptimeSeconds() int64    { if x != nil { return x.UptimeSeconds }; return 0 }
func (x *Heartbeat) GetCpuUsage() float64       { if x != nil { return x.CpuUsage }; return 0 }
func (x *Heartbeat) GetMemoryUsage() float64    { if x != nil { return x.MemoryUsage }; return 0 }
func (x *Heartbeat) GetActiveBansCount() int32  { if x != nil { return x.ActiveBansCount }; return 0 }

type HeartbeatResponse struct {
	state               protoimpl.MessageState `protogen:"open.v1"`
	Acknowledged        bool                   `protobuf:"varint,1,opt,name=acknowledged,proto3" json:"acknowledged,omitempty"`
	SyncIntervalSeconds int32                  `protobuf:"varint,2,opt,name=sync_interval_seconds,json=syncIntervalSeconds,proto3" json:"sync_interval_seconds,omitempty"`
	unknownFields       protoimpl.UnknownFields
	sizeCache           protoimpl.SizeCache
}

func (x *HeartbeatResponse) Reset() {
	*x = HeartbeatResponse{}
	mi := &file_copsec_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HeartbeatResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HeartbeatResponse) ProtoMessage() {}

func (x *HeartbeatResponse) ProtoReflect() protoreflect.Message {
	mi := &file_copsec_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *HeartbeatResponse) GetAcknowledged() bool          { if x != nil { return x.Acknowledged }; return false }
func (x *HeartbeatResponse) GetSyncIntervalSeconds() int32 { if x != nil { return x.SyncIntervalSeconds }; return 0 }

type SOARCommand struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	CommandId       string                 `protobuf:"bytes,1,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	ActionType      string                 `protobuf:"bytes,2,opt,name=action_type,json=actionType,proto3" json:"action_type,omitempty"`
	TargetIp        string                 `protobuf:"bytes,3,opt,name=target_ip,json=targetIp,proto3" json:"target_ip,omitempty"`
	DurationSeconds int64                  `protobuf:"varint,4,opt,name=duration_seconds,json=durationSeconds,proto3" json:"duration_seconds,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *SOARCommand) Reset() {
	*x = SOARCommand{}
	mi := &file_copsec_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SOARCommand) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SOARCommand) ProtoMessage() {}

func (x *SOARCommand) ProtoReflect() protoreflect.Message {
	mi := &file_copsec_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *SOARCommand) GetCommandId() string      { if x != nil { return x.CommandId }; return "" }
func (x *SOARCommand) GetActionType() string     { if x != nil { return x.ActionType }; return "" }
func (x *SOARCommand) GetTargetIp() string       { if x != nil { return x.TargetIp }; return "" }
func (x *SOARCommand) GetDurationSeconds() int64 { if x != nil { return x.DurationSeconds }; return 0 }

type CommandAck struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	CommandId     string                 `protobuf:"bytes,1,opt,name=command_id,json=commandId,proto3" json:"command_id,omitempty"`
	Success       bool                   `protobuf:"varint,2,opt,name=success,proto3" json:"success,omitempty"`
	Output        string                 `protobuf:"bytes,3,opt,name=output,proto3" json:"output,omitempty"`
	TimestampMs   int64                  `protobuf:"varint,4,opt,name=timestamp_ms,json=timestampMs,proto3" json:"timestamp_ms,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CommandAck) Reset() {
	*x = CommandAck{}
	mi := &file_copsec_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CommandAck) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CommandAck) ProtoMessage() {}

func (x *CommandAck) ProtoReflect() protoreflect.Message {
	mi := &file_copsec_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (x *CommandAck) GetCommandId() string   { if x != nil { return x.CommandId }; return "" }
func (x *CommandAck) GetSuccess() bool       { if x != nil { return x.Success }; return false }
func (x *CommandAck) GetOutput() string      { if x != nil { return x.Output }; return "" }
func (x *CommandAck) GetTimestampMs() int64  { if x != nil { return x.TimestampMs }; return 0 }

var file_copsec_proto_msgTypes = make([]protoimpl.MessageInfo, 6)

// -------------------------------------------------------------
// Client API
// -------------------------------------------------------------

type CopsecStreamServiceClient interface {
	StreamEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[LogEvent, StreamAck], error)
	SendHeartbeat(ctx context.Context, in *Heartbeat, opts ...grpc.CallOption) (*HeartbeatResponse, error)
	SyncCommands(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[CommandAck, SOARCommand], error)
}

type copsecStreamServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewCopsecStreamServiceClient(cc grpc.ClientConnInterface) CopsecStreamServiceClient {
	return &copsecStreamServiceClient{cc}
}

func (c *copsecStreamServiceClient) StreamEvents(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[LogEvent, StreamAck], error) {
	cStream, err := c.cc.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "StreamEvents",
		ClientStreams: true,
	}, "/copsec.CopsecStreamService/StreamEvents", opts...)
	if err != nil {
		return nil, err
	}
	x := &copsecStreamServiceStreamEventsClient{ClientStream: cStream}
	return x, nil
}

type CopsecStreamService_StreamEventsClient = grpc.ClientStreamingClient[LogEvent, StreamAck]
type copsecStreamServiceStreamEventsClient struct {
	grpc.ClientStream
}

func (x *copsecStreamServiceStreamEventsClient) Send(m *LogEvent) error {
	return x.ClientStream.SendMsg(m)
}

func (x *copsecStreamServiceStreamEventsClient) CloseAndRecv() (*StreamAck, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(StreamAck)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *copsecStreamServiceClient) SendHeartbeat(ctx context.Context, in *Heartbeat, opts ...grpc.CallOption) (*HeartbeatResponse, error) {
	out := new(HeartbeatResponse)
	err := c.cc.Invoke(ctx, "/copsec.CopsecStreamService/SendHeartbeat", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *copsecStreamServiceClient) SyncCommands(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[CommandAck, SOARCommand], error) {
	cStream, err := c.cc.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "SyncCommands",
		ServerStreams: true,
		ClientStreams: true,
	}, "/copsec.CopsecStreamService/SyncCommands", opts...)
	if err != nil {
		return nil, err
	}
	x := &copsecStreamServiceSyncCommandsClient{ClientStream: cStream}
	return x, nil
}

type CopsecStreamService_SyncCommandsClient = grpc.BidiStreamingClient[CommandAck, SOARCommand]
type copsecStreamServiceSyncCommandsClient struct {
	grpc.ClientStream
}

func (x *copsecStreamServiceSyncCommandsClient) Send(m *CommandAck) error {
	return x.ClientStream.SendMsg(m)
}

func (x *copsecStreamServiceSyncCommandsClient) Recv() (*SOARCommand, error) {
	m := new(SOARCommand)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// -------------------------------------------------------------
// Server API
// -------------------------------------------------------------

type CopsecStreamServiceServer interface {
	StreamEvents(grpc.ClientStreamingServer[LogEvent, StreamAck]) error
	SendHeartbeat(context.Context, *Heartbeat) (*HeartbeatResponse, error)
	SyncCommands(grpc.BidiStreamingServer[CommandAck, SOARCommand]) error
	mustEmbedUnimplementedCopsecStreamServiceServer()
}

type UnimplementedCopsecStreamServiceServer struct{}

func (UnimplementedCopsecStreamServiceServer) StreamEvents(grpc.ClientStreamingServer[LogEvent, StreamAck]) error {
	return status.Errorf(codes.Unimplemented, "method StreamEvents not implemented")
}
func (UnimplementedCopsecStreamServiceServer) SendHeartbeat(context.Context, *Heartbeat) (*HeartbeatResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SendHeartbeat not implemented")
}
func (UnimplementedCopsecStreamServiceServer) SyncCommands(grpc.BidiStreamingServer[CommandAck, SOARCommand]) error {
	return status.Errorf(codes.Unimplemented, "method SyncCommands not implemented")
}
func (UnimplementedCopsecStreamServiceServer) mustEmbedUnimplementedCopsecStreamServiceServer() {}

type UnsafeCopsecStreamServiceServer interface {
	mustEmbedUnimplementedCopsecStreamServiceServer()
}

func RegisterCopsecStreamServiceServer(s grpc.ServiceRegistrar, srv CopsecStreamServiceServer) {
	s.RegisterService(&CopsecStreamService_ServiceDesc, srv)
}

var CopsecStreamService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "copsec.CopsecStreamService",
	HandlerType: (*CopsecStreamServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SendHeartbeat",
			Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interp grpc.UnaryServerInterceptor) (interface{}, error) {
				in := new(Heartbeat)
				if err := dec(in); err != nil {
					return nil, err
				}
				if interp == nil {
					return srv.(CopsecStreamServiceServer).SendHeartbeat(ctx, in)
				}
				info := &grpc.UnaryServerInfo{
					Server:     srv,
					FullMethod: "/copsec.CopsecStreamService/SendHeartbeat",
				}
				handler := func(ctx context.Context, req interface{}) (interface{}, error) {
					return srv.(CopsecStreamServiceServer).SendHeartbeat(ctx, req.(*Heartbeat))
				}
				return interp(ctx, in, info, handler)
			},
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName: "StreamEvents",
			Handler: func(srv interface{}, stream grpc.ServerStream) error {
				return srv.(CopsecStreamServiceServer).StreamEvents(stream.(grpc.ClientStreamingServer[LogEvent, StreamAck]))
			},
			ClientStreams: true,
		},
		{
			StreamName: "SyncCommands",
			Handler: func(srv interface{}, stream grpc.ServerStream) error {
				return srv.(CopsecStreamServiceServer).SyncCommands(stream.(grpc.BidiStreamingServer[CommandAck, SOARCommand]))
			},
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "copsec.proto",
}
