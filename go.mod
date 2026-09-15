module github.com/copsec

go 1.25.0

replace (
	github.com/copsec/collector => ./collector
	github.com/copsec/controller => ./controller
)

require (
	github.com/cilium/ebpf v0.22.0
	golang.org/x/sys v0.47.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
