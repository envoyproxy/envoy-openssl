#pragma once

#include "envoy/upstream/load_balancer.h"

#include "source/common/upstream/load_balancer_factory_base.h"

#include "test/integration/load_balancers/config.pb.h"
#include "test/test_common/registry.h"

namespace Envoy {

class ThreadAwareLbImpl : public Upstream::ThreadAwareLoadBalancer {
public:
  ThreadAwareLbImpl() : host_(nullptr) {}
  ThreadAwareLbImpl(const Upstream::HostSharedPtr& host) : host_(host) {}

  Upstream::LoadBalancerFactorySharedPtr factory() override {
    return std::make_shared<LbFactory>(host_);
  }
  void initialize() override {}

private:
  class LbImpl : public Upstream::LoadBalancer {
  public:
    LbImpl(const Upstream::HostSharedPtr& host) : host_(host) {}

    Upstream::HostConstSharedPtr chooseHost(Upstream::LoadBalancerContext*) override {
      return host_;
    }
    Upstream::HostConstSharedPtr peekAnotherHost(Upstream::LoadBalancerContext*) override {
      return nullptr;
    }
    OptRef<Envoy::Http::ConnectionPool::ConnectionLifetimeCallbacks> lifetimeCallbacks() override {
      return {};
    }
    absl::optional<Upstream::SelectedPoolAndConnection>
    selectExistingConnection(Upstream::LoadBalancerContext*, const Upstream::Host&,
                             std::vector<uint8_t>&) override {
      return {};
    }

    const Upstream::HostSharedPtr host_;
  };

  class LbFactory : public Upstream::LoadBalancerFactory {
  public:
    LbFactory(const Upstream::HostSharedPtr& host) : host_(host) {}

    Upstream::LoadBalancerPtr create() override { return std::make_unique<LbImpl>(host_); }
    Upstream::LoadBalancerPtr create(Upstream::LoadBalancerParams) override { return create(); }

    const Upstream::HostSharedPtr host_;
  };

  const Upstream::HostSharedPtr host_;
};

class CustomLbFactory : public Upstream::TypedLoadBalancerFactoryBase<
                            ::test::integration::custom_lb::CustomLbConfig> {
public:
  CustomLbFactory() : TypedLoadBalancerFactoryBase("envoy.load_balancers.custom_lb") {}

  Upstream::ThreadAwareLoadBalancerPtr create(const Upstream::ClusterInfo&,
                                              const Upstream::PrioritySet&, Runtime::Loader&,
                                              Random::RandomGenerator&, TimeSource&) override {
    return std::make_unique<ThreadAwareLbImpl>();
  }
};

} // namespace Envoy
