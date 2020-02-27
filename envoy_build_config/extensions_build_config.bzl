# See bazel/README.md for details on how this system works.
EXTENSIONS = {
    #
    # Access loggers
    #

    "envoy.access_loggers.file":                        "@envoy//source/extensions/access_loggers/file:config",
    "envoy.access_loggers.http_grpc":                   "@envoy//source/extensions/access_loggers/grpc:http_config",
    "envoy.access_loggers.tcp_grpc":                    "@envoy//source/extensions/access_loggers/grpc:tcp_config",

    #
    # Clusters
    #

    "envoy.clusters.aggregate":                         "@envoy//source/extensions/clusters/aggregate:cluster",
    "envoy.clusters.dynamic_forward_proxy":             "@envoy//source/extensions/clusters/dynamic_forward_proxy:cluster",
    "envoy.clusters.redis":                             "@envoy//source/extensions/clusters/redis:redis_cluster",

    #
    # gRPC Credentials Plugins
    #

    "envoy.grpc_credentials.file_based_metadata":       "@envoy//source/extensions/grpc_credentials/file_based_metadata:config",
    "envoy.grpc_credentials.aws_iam":                   "@envoy_openssl//source/extensions/grpc_credentials/aws_iam:config",

    #
    # Health checkers
    #

    "envoy.health_checkers.redis":                      "@envoy//source/extensions/health_checkers/redis:config",

    #
    # HTTP filters
    #

    "envoy.filters.http.adaptive_concurrency":          "@envoy//source/extensions/filters/http/adaptive_concurrency:config",
    "envoy.filters.http.aws_request_signing":           "@envoy_openssl//source/extensions/filters/http/aws_request_signing:config",
    "envoy.filters.http.buffer":                        "@envoy//source/extensions/filters/http/buffer:config",
    "envoy.filters.http.cache":                         "@envoy//source/extensions/filters/http/cache:config",
    "envoy.filters.http.cors":                          "@envoy//source/extensions/filters/http/cors:config",
    "envoy.filters.http.csrf":                          "@envoy//source/extensions/filters/http/csrf:config",
    "envoy.filters.http.dynamic_forward_proxy":         "@envoy//source/extensions/filters/http/dynamic_forward_proxy:config",
    "envoy.filters.http.dynamo":                        "@envoy//source/extensions/filters/http/dynamo:config",
    "envoy.filters.http.ext_authz":                     "@envoy//source/extensions/filters/http/ext_authz:config",
    "envoy.filters.http.fault":                         "@envoy//source/extensions/filters/http/fault:config",
    "envoy.filters.http.grpc_http1_bridge":             "@envoy//source/extensions/filters/http/grpc_http1_bridge:config",
    "envoy.filters.http.grpc_http1_reverse_bridge":     "@envoy//source/extensions/filters/http/grpc_http1_reverse_bridge:config",
    "envoy.filters.http.grpc_json_transcoder":          "@envoy//source/extensions/filters/http/grpc_json_transcoder:config",
    "envoy.filters.http.grpc_stats":                    "@envoy//source/extensions/filters/http/grpc_stats:config",
    "envoy.filters.http.grpc_web":                      "@envoy//source/extensions/filters/http/grpc_web:config",
    "envoy.filters.http.gzip":                          "@envoy//source/extensions/filters/http/gzip:config",
    "envoy.filters.http.header_to_metadata":            "@envoy//source/extensions/filters/http/header_to_metadata:config",
    "envoy.filters.http.health_check":                  "@envoy//source/extensions/filters/http/health_check:config",
    "envoy.filters.http.ip_tagging":                    "@envoy//source/extensions/filters/http/ip_tagging:config",
    "envoy.filters.http.jwt_authn":                     "@envoy//source/extensions/filters/http/jwt_authn:config",
    "envoy.filters.http.lua":                           "@envoy_openssl//source/extensions/filters/http/lua:config",
    "envoy.filters.http.on_demand":                     "@envoy//source/extensions/filters/http/on_demand:config",
    "envoy.filters.http.original_src":                  "@envoy//source/extensions/filters/http/original_src:config",
    "envoy.filters.http.ratelimit":                     "@envoy//source/extensions/filters/http/ratelimit:config",
    "envoy.filters.http.rbac":                          "@envoy//source/extensions/filters/http/rbac:config",
    "envoy.filters.http.router":                        "@envoy//source/extensions/filters/http/router:config",
    "envoy.filters.http.squash":                        "@envoy//source/extensions/filters/http/squash:config",
    "envoy.filters.http.tap":                           "@envoy//source/extensions/filters/http/tap:config",

    #
    # Listener filters
    #

    "envoy.filters.listener.http_inspector":            "@envoy//source/extensions/filters/listener/http_inspector:config",
    # NOTE: The original_dst filter is implicitly loaded if original_dst functionality is
    #       configured on the listener. Do not remove it in that case or configs will fail to load.
    "envoy.filters.listener.original_dst":              "@envoy//source/extensions/filters/listener/original_dst:config",
    "envoy.filters.listener.original_src":               "@envoy//source/extensions/filters/listener/original_src:config",
    # NOTE: The proxy_protocol filter is implicitly loaded if proxy_protocol functionality is
    #       configured on the listener. Do not remove it in that case or configs will fail to load.
    "envoy.filters.listener.proxy_protocol":            "@envoy//source/extensions/filters/listener/proxy_protocol:config",
    "envoy.filters.listener.tls_inspector":             "@envoy_openssl//source/extensions/filters/listener/tls_inspector:config",

    #
    # Network filters
    #

    "envoy.filters.network.client_ssl_auth":            "@envoy//source/extensions/filters/network/client_ssl_auth:config",
    "envoy.filters.network.dubbo_proxy":                "@envoy//source/extensions/filters/network/dubbo_proxy:config",
    "envoy.filters.network.echo":                       "@envoy//source/extensions/filters/network/echo:config",
    "envoy.filters.network.ext_authz":                  "@envoy//source/extensions/filters/network/ext_authz:config",
    "envoy.filters.network.http_connection_manager":    "@envoy//source/extensions/filters/network/http_connection_manager:config",
    # WiP
    "envoy.filters.network.kafka_broker":               "@envoy//source/extensions/filters/network/kafka:kafka_broker_config_lib",
    "envoy.filters.network.local_ratelimit":            "@envoy//source/extensions/filters/network/local_ratelimit:config",
    "envoy.filters.network.mongo_proxy":                "@envoy//source/extensions/filters/network/mongo_proxy:config",
    "envoy.filters.network.mysql_proxy":                "@envoy//source/extensions/filters/network/mysql_proxy:config",
    "envoy.filters.network.ratelimit":                  "@envoy//source/extensions/filters/network/ratelimit:config",
    "envoy.filters.network.rbac":                       "@envoy//source/extensions/filters/network/rbac:config",
    "envoy.filters.network.redis_proxy":                "@envoy//source/extensions/filters/network/redis_proxy:config",
    "envoy.filters.network.tcp_proxy":                  "@envoy//source/extensions/filters/network/tcp_proxy:config",
    "envoy.filters.network.thrift_proxy":               "@envoy//source/extensions/filters/network/thrift_proxy:config",
    "envoy.filters.network.sni_cluster":                "@envoy//source/extensions/filters/network/sni_cluster:config",
    "envoy.filters.network.zookeeper_proxy":            "@envoy//source/extensions/filters/network/zookeeper_proxy:config",

    #
    # UDP filters
    #

    "envoy.filters.udp_listener.udp_proxy":             "@envoy//source/extensions/filters/udp/udp_proxy:config",

    #
    # SSL
    #
    "envoy.common.crypto.utility_lib":                  "@envoy_openssl//source/extensions/common/crypto:utility_lib",

    #
    # Resource monitors
    #

    "envoy.resource_monitors.fixed_heap":               "@envoy//source/extensions/resource_monitors/fixed_heap:config",
    "envoy.resource_monitors.injected_resource":        "@envoy//source/extensions/resource_monitors/injected_resource:config",

    #
    # Stat sinks
    #

    "envoy.stat_sinks.dog_statsd":                      "@envoy//source/extensions/stat_sinks/dog_statsd:config",
    "envoy.stat_sinks.hystrix":                         "@envoy//source/extensions/stat_sinks/hystrix:config",
    "envoy.stat_sinks.metrics_service":                 "@envoy//source/extensions/stat_sinks/metrics_service:config",
    "envoy.stat_sinks.statsd":                          "@envoy//source/extensions/stat_sinks/statsd:config",

    #
    # Thrift filters
    #

    "envoy.filters.thrift.router":                      "@envoy//source/extensions/filters/network/thrift_proxy/router:config",
    "envoy.filters.thrift.ratelimit":                   "@envoy//source/extensions/filters/network/thrift_proxy/filters/ratelimit:config",

    #
    # Tracers
    #

    "envoy.tracers.dynamic_ot":                         "@envoy//source/extensions/tracers/dynamic_ot:config",
    "envoy.tracers.lightstep":                          "@envoy//source/extensions/tracers/lightstep:config",
    "envoy.tracers.datadog":                            "@envoy//source/extensions/tracers/datadog:config",
    "envoy.tracers.zipkin":                             "@envoy//source/extensions/tracers/zipkin:config",
    "envoy.tracers.opencensus":                         "@envoy//source/extensions/tracers/opencensus:config",
    # WiP
    "envoy.tracers.xray":                               "@envoy//source/extensions/tracers/xray:config",

    #
    # Transport sockets
    #

    "envoy.transport_sockets.alts":                     "@envoy//source/extensions/transport_sockets/alts:config",
    "envoy.transport_sockets.raw_buffer":               "@envoy//source/extensions/transport_sockets/raw_buffer:config",
    "envoy.transport_sockets.tap":                      "@envoy//source/extensions/transport_sockets/tap:config",
    "envoy.transport_sockets.tls":                      "@envoy_openssl//source/extensions/transport_sockets/tls:config",

    #
    # Retry host predicates
    #

    "envoy.retry_host_predicates.previous_hosts":       "@envoy//source/extensions/retry/host/previous_hosts:config",
    "envoy.retry_host_predicates.omit_canary_hosts":    "@envoy//source/extensions/retry/host/omit_canary_hosts:config",
    "envoy.retry_host_predicates.omit_host_metadata":   "@envoy//source/extensions/retry/host/omit_host_metadata:config",

    #
    # Retry priorities
    #

    "envoy.retry_priorities.previous_priorities":       "@envoy//source/extensions/retry/priority/previous_priorities:config",

    #
    # CacheFilter plugins
    #

    "envoy.filters.http.cache.simple_http_cache":       "@envoy//source/extensions/filters/http/cache/simple_http_cache:simple_http_cache_lib",
}

WINDOWS_EXTENSIONS = {
    #
    # Access loggers
    #

    "envoy.access_loggers.file":                        "@envoy//source/extensions/access_loggers/file:config",
    #"envoy.access_loggers.http_grpc":                   "@envoy//source/extensions/access_loggers/grpc:http_config",

    #
    # gRPC Credentials Plugins
    #

    #"envoy.grpc_credentials.file_based_metadata":      "@envoy//source/extensions/grpc_credentials/file_based_metadata:config",

    #
    # Health checkers
    #

    #"envoy.health_checkers.redis":                      "@envoy//source/extensions/health_checkers/redis:config",

    #
    # HTTP filters
    #

    #"envoy.filters.http.buffer":                        "@envoy//source/extensions/filters/http/buffer:config",
    #"envoy.filters.http.cors":                          "@envoy//source/extensions/filters/http/cors:config",
    #"envoy.filters.http.csrf":                          "@envoy//source/extensions/filters/http/csrf:config",
    #"envoy.filters.http.dynamo":                        "@envoy//source/extensions/filters/http/dynamo:config",
    #"envoy.filters.http.ext_authz":                     "@envoy//source/extensions/filters/http/ext_authz:config",
    #"envoy.filters.http.fault":                         "@envoy//source/extensions/filters/http/fault:config",
    #"envoy.filters.http.grpc_http1_bridge":             "@envoy//source/extensions/filters/http/grpc_http1_bridge:config",
    #"envoy.filters.http.grpc_json_transcoder":          "@envoy//source/extensions/filters/http/grpc_json_transcoder:config",
    #"envoy.filters.http.grpc_web":                      "@envoy//source/extensions/filters/http/grpc_web:config",
    #"envoy.filters.http.gzip":                          "@envoy//source/extensions/filters/http/gzip:config",
    #"envoy.filters.http.health_check":                  "@envoy//source/extensions/filters/http/health_check:config",
    #"envoy.filters.http.ip_tagging":                    "@envoy//source/extensions/filters/http/ip_tagging:config",
    #"envoy.filters.http.lua":                           "@envoy//source/extensions/filters/http/lua:config",
    #"envoy.filters.http.ratelimit":                     "@envoy//source/extensions/filters/http/ratelimit:config",
    #"envoy.filters.http.rbac":                          "@envoy//source/extensions/filters/http/rbac:config",
    #"envoy.filters.http.router":                        "@envoy//source/extensions/filters/http/router:config",
    #"envoy.filters.http.squash":                        "@envoy//source/extensions/filters/http/squash:config",

    #
    # Listener filters
    #

    # NOTE: The proxy_protocol filter is implicitly loaded if proxy_protocol functionality is
    #       configured on the listener. Do not remove it in that case or configs will fail to load.
    "envoy.filters.listener.proxy_protocol":            "@envoy//source/extensions/filters/listener/proxy_protocol:config",

    # NOTE: The original_dst filter is implicitly loaded if original_dst functionality is
    #       configured on the listener. Do not remove it in that case or configs will fail to load.
    #"envoy.filters.listener.original_dst":              "@envoy//source/extensions/filters/listener/original_dst:config",

    "envoy.filters.listener.tls_inspector":             "@envoy_openssl//source/extensions/filters/listener/tls_inspector:config",

    #
    # Network filters
    #

    "envoy.filters.network.client_ssl_auth":            "@envoy//source/extensions/filters/network/client_ssl_auth:config",
    #"envoy.filters.network.echo":                       "@envoy//source/extensions/filters/network/echo:config",
    #"envoy.filters.network.ext_authz":                  "@envoy//source/extensions/filters/network/ext_authz:config",
    #"envoy.filters.network.http_connection_manager":    "@envoy//source/extensions/filters/network/http_connection_manager:config",
    #"envoy.filters.network.mongo_proxy":                "@envoy//source/extensions/filters/network/mongo_proxy:config",
    #"envoy.filters.network.mysql_proxy":                "@envoy//source/extensions/filters/network/mysql_proxy:config",
    #"envoy.filters.network.redis_proxy":                "@envoy//source/extensions/filters/network/redis_proxy:config",
    #"envoy.filters.network.ratelimit":                  "@envoy//source/extensions/filters/network/ratelimit:config",
    "envoy.filters.network.tcp_proxy":                  "@envoy//source/extensions/filters/network/tcp_proxy:config",
    #"envoy.filters.network.thrift_proxy":               "@envoy//source/extensions/filters/network/thrift_proxy:config",
    #"envoy.filters.network.sni_cluster":                "@envoy//source/extensions/filters/network/sni_cluster:config",
    #"envoy.filters.network.zookeeper_proxy":            "@envoy//source/extensions/filters/network/zookeeper_proxy:config",

    #
    # Stat sinks
    #

    #"envoy.stat_sinks.dog_statsd":                      "@envoy//source/extensions/stat_sinks/dog_statsd:config",
    #"envoy.stat_sinks.metrics_service":                 "@envoy//source/extensions/stat_sinks/metrics_service:config",
    #"envoy.stat_sinks.statsd":                          "@envoy//source/extensions/stat_sinks/statsd:config",

    #
    # Tracers
    #

    #"envoy.tracers.dynamic_ot":                         "@envoy//source/extensions/tracers/dynamic_ot:config",
    #"envoy.tracers.lightstep":                          "@envoy//source/extensions/tracers/lightstep:config",
    #"envoy.tracers.zipkin":                             "@envoy//source/extensions/tracers/zipkin:config",

    #
    # Transport sockets
    #

    #"envoy.transport_sockets.tap":                      "@envoy//source/extensions/transport_sockets/tap:config",
}
