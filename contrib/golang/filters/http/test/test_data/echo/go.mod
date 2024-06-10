module example.com/echo

go 1.20

require (
	github.com/cncf/xds/go v0.0.0-20230112175826-46e39c7b9b43
	github.com/envoyproxy/envoy v1.24.0
)

require (
	golang.org/x/net v0.11.0 // indirect
	golang.org/x/sys v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55 // indirect
	google.golang.org/grpc v1.25.1 // indirect
)

require (
	github.com/envoyproxy/protoc-gen-validate v1.0.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	google.golang.org/protobuf v1.34.1
)

replace github.com/envoyproxy/envoy => ../../../../../../../
