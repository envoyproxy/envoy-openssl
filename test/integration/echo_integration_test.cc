#include "test/integration/integration.h"
#include "test/integration/utility.h"
#include "test/server/utility.h"
#include "test/test_common/utility.h"

namespace Envoy {

std::string echo_config;

class EchoIntegrationTest : public testing::TestWithParam<Network::Address::IpVersion>,
                            public BaseIntegrationTest {
public:
  EchoIntegrationTest() : BaseIntegrationTest(GetParam(), echo_config) {}

  // Called once by the gtest framework before any EchoIntegrationTests are run.
  static void SetUpTestSuite() {
    echo_config = ConfigHelper::BASE_CONFIG + R"EOF(
    filter_chains:
      filters:
        name: ratelimit
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.rate_limit.v2.RateLimit
          domain: foo
          stats_prefix: name
          descriptors: [{"key": "foo", "value": "bar"}]
      filters:
        name: envoy.filters.network.echo
      )EOF";
  }

  /**
   * Initializer for an individual test.
   */
  void SetUp() override { BaseIntegrationTest::initialize(); }

  /**
   *  Destructor for an individual test.
   */
  void TearDown() override {
    test_server_.reset();
    fake_upstreams_.clear();
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, EchoIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(EchoIntegrationTest, Hello) {
  Buffer::OwnedImpl buffer("hello");
  std::string response;
  RawConnectionDriver connection(
      lookupPort("listener_0"), buffer,
      [&](Network::ClientConnection&, const Buffer::Instance& data) -> void {
        response.append(data.toString());
        connection.close();
      },
      version_);

  connection.run();
  EXPECT_EQ("hello", response);
}

TEST_P(EchoIntegrationTest, AddRemoveListener) {
  const std::string json = TestEnvironment::substitute(R"EOF(
name: new_listener
address:
  socket_address:
    address: "{{ ip_loopback_address }}"
    port_value: 0
filter_chains:
- filters:
  - name: envoy.filters.network.echo
  )EOF",
                                                       GetParam());

  // Add the listener.
  ConditionalInitializer listener_added_by_worker;
  ConditionalInitializer listener_added_by_manager;
  test_server_->setOnWorkerListenerAddedCb(
      [&listener_added_by_worker]() -> void { listener_added_by_worker.setReady(); });
  test_server_->server().dispatcher().post([this, json, &listener_added_by_manager]() -> void {
    EXPECT_TRUE(test_server_->server().listenerManager().addOrUpdateListener(
        Server::parseListenerFromV2Yaml(json), "", true));
    listener_added_by_manager.setReady();
  });
  listener_added_by_worker.waitReady();
  listener_added_by_manager.waitReady();

  EXPECT_EQ(2UL, test_server_->server().listenerManager().listeners().size());
  uint32_t new_listener_port = test_server_->server()
                                   .listenerManager()
                                   .listeners()[1]
                                   .get()
                                   .listenSocketFactory()
                                   .localAddress()
                                   ->ip()
                                   ->port();

  Buffer::OwnedImpl buffer("hello");
  std::string response;
  RawConnectionDriver connection(
      new_listener_port, buffer,
      [&](Network::ClientConnection&, const Buffer::Instance& data) -> void {
        response.append(data.toString());
        connection.close();
      },
      version_);
  connection.run();
  EXPECT_EQ("hello", response);

  // Remove the listener.
  ConditionalInitializer listener_removed;
  test_server_->setOnWorkerListenerRemovedCb(
      [&listener_removed]() -> void { listener_removed.setReady(); });
  test_server_->server().dispatcher().post([this]() -> void {
    EXPECT_TRUE(test_server_->server().listenerManager().removeListener("new_listener"));
  });
  listener_removed.waitReady();

  // Now connect. This should fail.
  // Allow for a few attempts, in order to handle a race (likely due to lack of
  // LEV_OPT_CLOSE_ON_FREE, which would break listener reuse)
  //
  // In order for this test to work, it must be tagged as "exclusive" in its
  // build file. Otherwise, it's possible that when the listener is destroyed
  // above, another test would start listening on the released port, and this
  // connect would unexpectedly succeed.
  bool connect_fail = false;
  for (int i = 0; i < 10; ++i) {
    RawConnectionDriver connection2(
        new_listener_port, buffer,
        [&](Network::ClientConnection&, const Buffer::Instance&) -> void { FAIL(); }, version_);
    while (connection2.connecting()) {
      // Don't busy loop, but macOS often needs a moment to decide this connection isn't happening.
      timeSystem().sleep(std::chrono::milliseconds(10));

      connection2.run(Event::Dispatcher::RunType::NonBlock);
    }
    if (connection2.connection().state() == Network::Connection::State::Closed) {
      connect_fail = true;
      break;
    } else {
      connection2.close();
    }
  }
  ASSERT_TRUE(connect_fail);
}

} // namespace Envoy
