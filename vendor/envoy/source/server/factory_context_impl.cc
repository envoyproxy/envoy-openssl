#include "source/server/factory_context_impl.h"

namespace Envoy {
namespace Server {

FactoryContextImpl::FactoryContextImpl(Server::Instance& server,
                                       const envoy::config::listener::v3::Listener& config,
                                       Network::DrainDecision& drain_decision,
                                       Stats::Scope& global_scope, Stats::Scope& listener_scope,
                                       bool is_quic)
    : server_(server), config_(config), drain_decision_(drain_decision),
      global_scope_(global_scope), listener_scope_(listener_scope), is_quic_(is_quic) {}

AccessLog::AccessLogManager& FactoryContextImpl::accessLogManager() {
  return server_.accessLogManager();
}
Upstream::ClusterManager& FactoryContextImpl::clusterManager() { return server_.clusterManager(); }
Event::Dispatcher& FactoryContextImpl::mainThreadDispatcher() { return server_.dispatcher(); }
const Server::Options& FactoryContextImpl::options() { return server_.options(); }
Grpc::Context& FactoryContextImpl::grpcContext() { return server_.grpcContext(); }
Router::Context& FactoryContextImpl::routerContext() { return server_.routerContext(); }
bool FactoryContextImpl::healthCheckFailed() { return server_.healthCheckFailed(); }
Http::Context& FactoryContextImpl::httpContext() { return server_.httpContext(); }
Init::Manager& FactoryContextImpl::initManager() { return server_.initManager(); }
const LocalInfo::LocalInfo& FactoryContextImpl::localInfo() const { return server_.localInfo(); }
Envoy::Runtime::Loader& FactoryContextImpl::runtime() { return server_.runtime(); }
Stats::Scope& FactoryContextImpl::scope() { return global_scope_; }
Singleton::Manager& FactoryContextImpl::singletonManager() { return server_.singletonManager(); }
OverloadManager& FactoryContextImpl::overloadManager() { return server_.overloadManager(); }
ThreadLocal::SlotAllocator& FactoryContextImpl::threadLocal() { return server_.threadLocal(); }
OptRef<Admin> FactoryContextImpl::admin() { return server_.admin(); }
TimeSource& FactoryContextImpl::timeSource() { return server_.timeSource(); }
ProtobufMessage::ValidationContext& FactoryContextImpl::messageValidationContext() {
  return server_.messageValidationContext();
}
ProtobufMessage::ValidationVisitor& FactoryContextImpl::messageValidationVisitor() {
  return server_.messageValidationContext().staticValidationVisitor();
}
Api::Api& FactoryContextImpl::api() { return server_.api(); }
ServerLifecycleNotifier& FactoryContextImpl::lifecycleNotifier() {
  return server_.lifecycleNotifier();
}
ProcessContextOptRef FactoryContextImpl::processContext() { return server_.processContext(); }
Configuration::ServerFactoryContext& FactoryContextImpl::getServerFactoryContext() const {
  return server_.serverFactoryContext();
}
Configuration::TransportSocketFactoryContext&
FactoryContextImpl::getTransportSocketFactoryContext() const {
  return server_.transportSocketFactoryContext();
}
const envoy::config::core::v3::Metadata& FactoryContextImpl::listenerMetadata() const {
  return config_.metadata();
}
const Envoy::Config::TypedMetadata& FactoryContextImpl::listenerTypedMetadata() const {
  // TODO(nareddyt): Needs an implementation for this context. Currently not used.
  PANIC("not implemented");
}
envoy::config::core::v3::TrafficDirection FactoryContextImpl::direction() const {
  return config_.traffic_direction();
}
Network::DrainDecision& FactoryContextImpl::drainDecision() { return drain_decision_; }
Stats::Scope& FactoryContextImpl::listenerScope() { return listener_scope_; }
bool FactoryContextImpl::isQuicListener() const { return is_quic_; }

} // namespace Server
} // namespace Envoy
