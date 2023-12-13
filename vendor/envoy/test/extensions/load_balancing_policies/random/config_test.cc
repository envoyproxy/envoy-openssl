#include "envoy/config/core/v3/extension.pb.h"

#include "source/extensions/load_balancing_policies/random/config.h"

#include "test/mocks/server/factory_context.h"
#include "test/mocks/upstream/cluster_info.h"
#include "test/mocks/upstream/priority_set.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace LoadBalancingPolices {
namespace Random {
namespace {

TEST(RandomConfigTest, ValidateFail) {
  NiceMock<Server::Configuration::MockFactoryContext> context;
  NiceMock<Upstream::MockClusterInfo> cluster_info;
  NiceMock<Upstream::MockPrioritySet> main_thread_priority_set;
  NiceMock<Upstream::MockPrioritySet> thread_local_priority_set;

  envoy::config::core::v3::TypedExtensionConfig config;
  config.set_name("envoy.load_balancing_policies.random");
  envoy::extensions::load_balancing_policies::random::v3::Random config_msg;
  config.mutable_typed_config()->PackFrom(config_msg);

  auto& factory = Config::Utility::getAndCheckFactory<Upstream::TypedLoadBalancerFactory>(config);
  EXPECT_EQ("envoy.load_balancing_policies.random", factory.name());

  auto message_ptr = factory.createEmptyConfigProto();
  EXPECT_CALL(cluster_info, loadBalancingPolicy()).WillOnce(testing::ReturnRef(message_ptr));

  auto thread_aware_lb =
      factory.create(cluster_info, main_thread_priority_set, context.runtime_loader_,
                     context.api_.random_, context.time_system_);
  EXPECT_NE(nullptr, thread_aware_lb);

  thread_aware_lb->initialize();

  auto thread_local_lb_factory = thread_aware_lb->factory();
  EXPECT_NE(nullptr, thread_local_lb_factory);

  auto thread_local_lb = thread_local_lb_factory->create({thread_local_priority_set, nullptr});
  EXPECT_NE(nullptr, thread_local_lb);

  EXPECT_DEATH(thread_local_lb_factory->create(), "not implemented");
}

} // namespace
} // namespace Random
} // namespace LoadBalancingPolices
} // namespace Extensions
} // namespace Envoy
