#include "source/common/tracing/common_values.h"

#include "test/mocks/server/factory_context.h"
#include "test/test_common/registry.h"
#include "test/test_common/utility.h"

#include "contrib/generic_proxy/filters/network/source/router/router.h"
#include "contrib/generic_proxy/filters/network/test/fake_codec.h"
#include "contrib/generic_proxy/filters/network/test/mocks/codec.h"
#include "contrib/generic_proxy/filters/network/test/mocks/filter.h"
#include "contrib/generic_proxy/filters/network/test/mocks/route.h"
#include "gtest/gtest.h"

using testing::ByMove;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace GenericProxy {
namespace Router {
namespace {

#define ONLY_RUN_TEST_WITH_PARAM(param)                                                            \
  if (GetParam() != param) {                                                                       \
    return;                                                                                        \
  }

struct TestParameters {
  bool operator!=(const TestParameters& other) const {
    return with_tracing != other.with_tracing || bind_upstream != other.bind_upstream ||
           bound_already != other.bound_already;
  }

  bool with_tracing{};
  bool bind_upstream{};
  bool bound_already{};
};

class RouterFilterTest : public testing::TestWithParam<TestParameters> {
public:
  RouterFilterTest() {
    // Common mock calls.
    ON_CALL(mock_filter_callback_, dispatcher()).WillByDefault(ReturnRef(dispatcher_));
    ON_CALL(mock_filter_callback_, activeSpan()).WillByDefault(ReturnRef(active_span_));
    ON_CALL(mock_filter_callback_, downstreamCodec()).WillByDefault(ReturnRef(mock_codec_factory_));
    ON_CALL(mock_filter_callback_, streamInfo()).WillByDefault(ReturnRef(mock_stream_info_));
  }

  void setup(ExtendedOptions request_options = ExtendedOptions{}) {
    auto parameter = GetParam();
    protocol_options_ = ProtocolOptions{parameter.bind_upstream};
    bound_already_ = parameter.bound_already;
    with_tracing_ = parameter.with_tracing;

    request_options_ = request_options;

    ON_CALL(mock_codec_factory_, protocolOptions()).WillByDefault(Return(protocol_options_));
    ON_CALL(mock_filter_callback_, requestOptions()).WillByDefault(Return(request_options_));

    filter_ = std::make_shared<Router::RouterFilter>(factory_context_);
    filter_->setDecoderFilterCallbacks(mock_filter_callback_);

    request_ = std::make_unique<FakeStreamCodecFactory::FakeRequest>();
  }

  void cleanUp() {
    filter_->onDestroy();
    filter_.reset();
    request_.reset();
  }

  void expectSetUpstreamCallback() {

    if (!protocol_options_.bindUpstreamConnection()) {
      // New connection and response decoder will be created for this upstream request.
      auto response_decoder = std::make_unique<NiceMock<MockResponseDecoder>>();
      mock_response_decoder_ = response_decoder.get();
      EXPECT_CALL(mock_codec_factory_, responseDecoder())
          .WillOnce(Return(ByMove(std::move(response_decoder))));

      EXPECT_CALL(factory_context_.cluster_manager_.thread_local_cluster_.tcp_conn_pool_,
                  newConnection(_));
      return;
    }

    // Set if the bound upstream manager is set.
    if (!bound_already_) {
      EXPECT_CALL(mock_filter_callback_, bindUpstreamConn(_))
          .WillOnce(Invoke([this](Upstream::TcpPoolData&&) {
            mock_filter_callback_.has_upstream_manager_ = true;
          }));
    } else {
      mock_filter_callback_.has_upstream_manager_ = true;
    }
    auto& upstream_manager = mock_filter_callback_.upstream_manager_;
    EXPECT_CALL(upstream_manager, registerUpstreamCallback(_, _))
        .WillOnce(Invoke([&upstream_manager](uint64_t stream_id, UpstreamBindingCallback& cb) {
          if (upstream_manager.call_on_bind_success_immediately_) {
            cb.onBindSuccess(upstream_manager.upstream_conn_, upstream_manager.upstream_host_);
            return;
          }

          if (upstream_manager.call_on_bind_failure_immediately_) {
            cb.onBindFailure(ConnectionPool::PoolFailureReason::RemoteConnectionFailure, "",
                             upstream_manager.upstream_host_);
            return;
          }
          upstream_manager.upstream_callbacks_[stream_id] = &cb;
        }));
  }

  void expectSetResponseCallback(PendingResponseCallback* expected_cb) {
    if (!protocol_options_.bindUpstreamConnection()) {
      EXPECT_CALL(*mock_response_decoder_, setDecoderCallback(_))
          .WillOnce(
              Invoke([expected_cb](ResponseDecoderCallback& cb) { EXPECT_EQ(expected_cb, &cb); }));
    } else {
      ON_CALL(mock_filter_callback_.upstream_manager_, registerResponseCallback(_, _))
          .WillByDefault(
              Invoke([this, expected_cb](uint64_t stream_id, PendingResponseCallback& cb) {
                EXPECT_EQ(expected_cb, &cb);
                mock_filter_callback_.upstream_manager_.response_callbacks_[stream_id] = &cb;
              }));
    }
  }

  void expectCancelConnect() {
    if (!protocol_options_.bindUpstreamConnection()) {
      EXPECT_CALL(
          factory_context_.cluster_manager_.thread_local_cluster_.tcp_conn_pool_.handles_.back(),
          cancel(_));
    } else {
      auto& upstream_manager = mock_filter_callback_.upstream_manager_;
      EXPECT_CALL(upstream_manager, unregisterUpstreamCallback(_))
          .WillOnce(Invoke([&upstream_manager](uint64_t stream_id) {
            upstream_manager.upstream_callbacks_.erase(stream_id);
          }));
      EXPECT_CALL(upstream_manager, unregisterResponseCallback(_))
          .WillOnce(Invoke([&upstream_manager](uint64_t stream_id) {
            upstream_manager.response_callbacks_.erase(stream_id);
          }));
    }
  }

  void expectConnectionClose() {
    if (!protocol_options_.bindUpstreamConnection()) {
      EXPECT_CALL(mock_upstream_connection_, close(Network::ConnectionCloseType::FlushWrite));
    } else {
      auto& upstream_manager = mock_filter_callback_.upstream_manager_;
      EXPECT_CALL(upstream_manager, unregisterUpstreamCallback(_))
          .WillOnce(Invoke([&upstream_manager](uint64_t stream_id) {
            upstream_manager.upstream_callbacks_.erase(stream_id);
          }));
      EXPECT_CALL(upstream_manager, unregisterResponseCallback(_))
          .WillOnce(Invoke([&upstream_manager](uint64_t stream_id) {
            upstream_manager.response_callbacks_.erase(stream_id);
          }));
    }
  }

  void notifyPoolFailure(Tcp::ConnectionPool::PoolFailureReason reason) {
    if (!protocol_options_.bindUpstreamConnection()) {
      factory_context_.cluster_manager_.thread_local_cluster_.tcp_conn_pool_.poolFailure(reason);
    } else {
      ASSERT(!mock_filter_callback_.upstream_manager_.upstream_callbacks_.empty());
      mock_filter_callback_.upstream_manager_.callOnBindFailure(0, reason);
    }
  }

  void notifyPoolReady() {
    if (!protocol_options_.bindUpstreamConnection()) {
      EXPECT_CALL(mock_upstream_connection_, write(_, _));
      factory_context_.cluster_manager_.thread_local_cluster_.tcp_conn_pool_.poolReady(
          mock_upstream_connection_);
    } else {
      ASSERT(!mock_filter_callback_.upstream_manager_.upstream_callbacks_.empty());
      EXPECT_CALL(mock_filter_callback_.upstream_manager_.upstream_conn_, write(_, _));
      mock_filter_callback_.upstream_manager_.callOnBindSuccess(0);
    }
  }

  void notifyConnectionClose(Network::ConnectionEvent event) {
    if (!protocol_options_.bindUpstreamConnection()) {
      ASSERT(!filter_->upstreamRequestsForTest().empty());
      auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();
      upstream_request->upstream_manager_->onEvent(event);
    } else {
      ASSERT(!mock_filter_callback_.upstream_manager_.response_callbacks_.empty());
      mock_filter_callback_.upstream_manager_.callOnConnectionClose(0, event);
    }
  }

  void notifyDecodingSuccess(ResponsePtr&& response, ExtendedOptions response_options) {
    if (!protocol_options_.bindUpstreamConnection()) {
      ASSERT(!filter_->upstreamRequestsForTest().empty());

      auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

      EXPECT_CALL(*mock_response_decoder_, decode(BufferStringEqual("test_1")))
          .WillOnce(Invoke([&](Buffer::Instance& buffer) {
            buffer.drain(buffer.length());
            upstream_request->onDecodingSuccess(std::move(response), response_options);
          }));

      Buffer::OwnedImpl test_buffer;
      test_buffer.add("test_1");

      upstream_request->upstream_manager_->onUpstreamData(test_buffer, false);
    } else {
      ASSERT(!mock_filter_callback_.upstream_manager_.response_callbacks_.empty());
      mock_filter_callback_.upstream_manager_.callOnDecodingSuccess(0, std::move(response),
                                                                    response_options);
    }
  }

  void notifyDecodingFailure() {
    if (!protocol_options_.bindUpstreamConnection()) {
      ASSERT(!filter_->upstreamRequestsForTest().empty());

      auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

      EXPECT_CALL(*mock_response_decoder_, decode(BufferStringEqual("test_1")))
          .WillOnce(Invoke([&](Buffer::Instance& buffer) {
            buffer.drain(buffer.length());
            upstream_request->onDecodingFailure();
          }));

      Buffer::OwnedImpl test_buffer;
      test_buffer.add("test_1");

      upstream_request->upstream_manager_->onUpstreamData(test_buffer, false);
    } else {
      ASSERT(!mock_filter_callback_.upstream_manager_.response_callbacks_.empty());
      mock_filter_callback_.upstream_manager_.callOnDecodingFailure(0);
    }
  }

  /**
   * Kick off a new upstream request.
   * @param with_tracing whether to set up tracing.
   * @param with_bound_upstream whether to set up bound upstream. This is only make sense when
   * protocol_options_.bindUpstreamConnection() is true.
   */
  void kickOffNewUpstreamRequest() {
    EXPECT_CALL(mock_filter_callback_, routeEntry()).WillOnce(Return(&mock_route_entry_));

    const std::string cluster_name = "cluster_0";

    EXPECT_CALL(mock_route_entry_, clusterName()).WillRepeatedly(ReturnRef(cluster_name));
    factory_context_.cluster_manager_.initializeThreadLocalClusters({cluster_name});

    expectSetUpstreamCallback();

    if (with_tracing_) {
      EXPECT_CALL(mock_filter_callback_, tracingConfig())
          .WillOnce(Return(OptRef<const Tracing::Config>{tracing_config_}));
      EXPECT_CALL(active_span_, spawnChild_(_, "router observability_name egress", _))
          .WillOnce(Invoke([this](const Tracing::Config&, const std::string&, SystemTime) {
            child_span_ = new NiceMock<Tracing::MockSpan>();
            return child_span_;
          }));
    } else {
      EXPECT_CALL(mock_filter_callback_, tracingConfig())
          .WillOnce(Return(OptRef<const Tracing::Config>{}));
    }

    auto request_encoder = std::make_unique<NiceMock<MockRequestEncoder>>();
    mock_request_encoder_ = request_encoder.get();
    EXPECT_CALL(mock_codec_factory_, requestEncoder())
        .WillOnce(Return(testing::ByMove(std::move(request_encoder))));

    EXPECT_EQ(filter_->onStreamDecoded(*request_), FilterStatus::StopIteration);
    EXPECT_EQ(1, filter_->upstreamRequestsForTest().size());
  }

  NiceMock<Server::Configuration::MockFactoryContext> factory_context_;
  NiceMock<Envoy::Event::MockDispatcher> dispatcher_;

  NiceMock<MockDecoderFilterCallback> mock_filter_callback_;
  NiceMock<StreamInfo::MockStreamInfo> mock_stream_info_;
  NiceMock<Network::MockClientConnection> mock_upstream_connection_;
  NiceMock<MockCodecFactory> mock_codec_factory_;

  NiceMock<MockRequestEncoder>* mock_request_encoder_{};
  NiceMock<MockResponseDecoder>* mock_response_decoder_{};

  NiceMock<MockRouteEntry> mock_route_entry_;

  std::shared_ptr<Router::RouterFilter> filter_;
  ProtocolOptions protocol_options_;
  bool bound_already_{};

  ExtendedOptions request_options_;
  std::unique_ptr<FakeStreamCodecFactory::FakeRequest> request_;

  NiceMock<Tracing::MockConfig> tracing_config_;
  NiceMock<Tracing::MockSpan> active_span_;
  NiceMock<Tracing::MockSpan>* child_span_{};
  bool with_tracing_{};
};

std::vector<TestParameters> getTestParameters() {
  std::vector<TestParameters> ret;

  ret.push_back({false, false, false});
  ret.push_back({true, true, false});
  ret.push_back({true, true, true});

  return ret;
}

std::string testParameterToString(const testing::TestParamInfo<TestParameters>& params) {
  return fmt::format("with_tracing_{}_bind_upstream_{}_bound_already_{}",
                     params.param.with_tracing ? "true" : "false",
                     params.param.bind_upstream ? "true" : "false",
                     params.param.bound_already ? "true" : "false");
}

INSTANTIATE_TEST_SUITE_P(GenericRoute, RouterFilterTest, testing::ValuesIn(getTestParameters()),
                         testParameterToString);

TEST_P(RouterFilterTest, OnStreamDecodedAndNoRouteEntry) {
  setup();

  EXPECT_CALL(mock_filter_callback_, routeEntry()).WillOnce(Return(nullptr));
  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(status.message(), "route_not_found");
      }));

  EXPECT_EQ(filter_->onStreamDecoded(*request_), FilterStatus::StopIteration);
  cleanUp();
}

TEST_P(RouterFilterTest, NoUpstreamCluster) {
  setup();

  EXPECT_CALL(mock_filter_callback_, routeEntry()).WillOnce(Return(&mock_route_entry_));

  const std::string cluster_name = "cluster_0";

  EXPECT_CALL(mock_route_entry_, clusterName()).WillRepeatedly(ReturnRef(cluster_name));

  // No upstream cluster.
  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(status.message(), "cluster_not_found");
      }));

  filter_->onStreamDecoded(*request_);
  cleanUp();
}

TEST_P(RouterFilterTest, UpstreamClusterMaintainMode) {
  setup();

  EXPECT_CALL(mock_filter_callback_, routeEntry()).WillOnce(Return(&mock_route_entry_));

  const std::string cluster_name = "cluster_0";

  EXPECT_CALL(mock_route_entry_, clusterName()).WillRepeatedly(ReturnRef(cluster_name));

  factory_context_.cluster_manager_.initializeThreadLocalClusters({cluster_name});

  // Maintain mode.
  EXPECT_CALL(*factory_context_.cluster_manager_.thread_local_cluster_.cluster_.info_,
              maintenanceMode())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(status.message(), "cluster_maintain_mode");
      }));

  filter_->onStreamDecoded(*request_);
  cleanUp();
}

TEST_P(RouterFilterTest, UpstreamClusterNoHealthyUpstream) {
  setup();

  EXPECT_CALL(mock_filter_callback_, routeEntry()).WillOnce(Return(&mock_route_entry_));

  const std::string cluster_name = "cluster_0";

  EXPECT_CALL(mock_route_entry_, clusterName()).WillRepeatedly(ReturnRef(cluster_name));

  factory_context_.cluster_manager_.initializeThreadLocalClusters({cluster_name});

  // No conn pool.
  EXPECT_CALL(factory_context_.cluster_manager_.thread_local_cluster_, tcpConnPool(_, _))
      .WillOnce(Return(absl::nullopt));

  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(status.message(), "no_healthy_upstream");
      }));

  filter_->onStreamDecoded(*request_);

  cleanUp();
}

TEST_P(RouterFilterTest, KickOffNormalUpstreamRequest) {
  setup();
  kickOffNewUpstreamRequest();

  cleanUp();
}

TEST_P(RouterFilterTest, UpstreamRequestResetBeforePoolCallback) {
  setup();
  kickOffNewUpstreamRequest();

  if (with_tracing_) {
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().Error, "true"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().ErrorReason, "local_reset"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().Component, "proxy"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().ResponseFlags, "-"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().UpstreamCluster, "fake_cluster"));
    EXPECT_CALL(*child_span_,
                setTag(Tracing::Tags::get().UpstreamClusterName, "observability_name"));

    EXPECT_CALL(*child_span_, finishSpan());
  }

  expectCancelConnect();

  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([this](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
        EXPECT_EQ(status.message(), "local_reset");
      }));

  filter_->upstreamRequestsForTest().begin()->get()->resetStream(StreamResetReason::LocalReset);
  EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
}

TEST_P(RouterFilterTest, UpstreamRequestPoolFailureConnctionOverflow) {
  setup();
  kickOffNewUpstreamRequest();

  if (with_tracing_) {
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().Error, "true"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().ErrorReason, "overflow"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().Component, "proxy"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().ResponseFlags, "-"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().UpstreamCluster, "fake_cluster"));
    EXPECT_CALL(*child_span_,
                setTag(Tracing::Tags::get().UpstreamClusterName, "observability_name"));
    EXPECT_CALL(*child_span_, finishSpan());
  }

  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(status.message(), "overflow");
      }));

  notifyPoolFailure(ConnectionPool::PoolFailureReason::Overflow);
}

TEST_P(RouterFilterTest, UpstreamRequestPoolFailureConnctionTimeout) {
  setup();
  kickOffNewUpstreamRequest();

  if (with_tracing_) {
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().Error, "true"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().ErrorReason, "connection_failure"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().Component, "proxy"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().ResponseFlags, "-"));
    EXPECT_CALL(*child_span_, setTag(Tracing::Tags::get().UpstreamCluster, "fake_cluster"));
    EXPECT_CALL(*child_span_,
                setTag(Tracing::Tags::get().UpstreamClusterName, "observability_name"));
    EXPECT_CALL(*child_span_, finishSpan());
  }

  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(status.message(), "connection_failure");
      }));

  notifyPoolFailure(ConnectionPool::PoolFailureReason::RemoteConnectionFailure);
}

TEST_P(RouterFilterTest, UpstreamRequestPoolReadyAndExpectNoResponse) {
  setup(ExtendedOptions{{}, false, false, false});
  kickOffNewUpstreamRequest();

  EXPECT_CALL(mock_filter_callback_, completeDirectly()).WillOnce(Invoke([this]() -> void {
    EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
  }));

  EXPECT_CALL(*mock_request_encoder_, encode(_, _))
      .WillOnce(Invoke([&](const Request&, RequestEncoderCallback& callback) -> void {
        Buffer::OwnedImpl buffer;
        buffer.add("hello");
        // Expect no response.
        callback.onEncodingSuccess(buffer);
      }));

  if (with_tracing_) {
    // Request complete directly.
    EXPECT_CALL(*child_span_, injectContext(_, _));
    EXPECT_CALL(*child_span_, setTag(_, _)).Times(testing::AnyNumber());
    EXPECT_CALL(*child_span_, finishSpan());
  }

  notifyPoolReady();
  EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
}

TEST_P(RouterFilterTest, UpstreamRequestPoolReadyButConnectionErrorBeforeResponse) {
  setup();
  kickOffNewUpstreamRequest();

  auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

  expectSetResponseCallback(upstream_request);

  EXPECT_CALL(*mock_request_encoder_, encode(_, _))
      .WillOnce(Invoke([&](const Request&, RequestEncoderCallback& callback) -> void {
        Buffer::OwnedImpl buffer;
        buffer.add("hello");
        // Expect response.
        callback.onEncodingSuccess(buffer);
      }));

  notifyPoolReady();

  EXPECT_NE(upstream_request->upstream_conn_, nullptr);

  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([this](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
        EXPECT_EQ(status.message(), "local_reset");
      }));

  // Mock connection close event.
  notifyConnectionClose(Network::ConnectionEvent::LocalClose);
}

TEST_P(RouterFilterTest, UpstreamRequestPoolReadyButConnectionTerminationBeforeResponse) {
  setup();
  kickOffNewUpstreamRequest();

  auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

  expectSetResponseCallback(upstream_request);

  EXPECT_CALL(*mock_request_encoder_, encode(_, _))
      .WillOnce(Invoke([&](const Request&, RequestEncoderCallback& callback) -> void {
        Buffer::OwnedImpl buffer;
        buffer.add("hello");
        // Expect response.
        callback.onEncodingSuccess(buffer);
      }));

  notifyPoolReady();

  EXPECT_NE(upstream_request->upstream_conn_, nullptr);

  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([this](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
        EXPECT_EQ(status.message(), "connection_termination");
      }));

  // Mock connection close event.
  notifyConnectionClose(Network::ConnectionEvent::RemoteClose);
}

TEST_P(RouterFilterTest, UpstreamRequestPoolReadyButStreamDestroyBeforeResponse) {
  setup();
  kickOffNewUpstreamRequest();

  auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

  expectSetResponseCallback(upstream_request);

  EXPECT_CALL(*mock_request_encoder_, encode(_, _))
      .WillOnce(Invoke([&](const Request&, RequestEncoderCallback& callback) -> void {
        Buffer::OwnedImpl buffer;
        buffer.add("hello");
        // Expect response.
        callback.onEncodingSuccess(buffer);
      }));

  notifyPoolReady();

  EXPECT_NE(upstream_request->upstream_conn_, nullptr);

  expectConnectionClose();

  filter_->onDestroy();
  // Do nothing for the second call.
  filter_->onDestroy();
}

TEST_P(RouterFilterTest, UpstreamRequestPoolReadyAndResponse) {
  setup();
  kickOffNewUpstreamRequest();

  auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

  expectSetResponseCallback(upstream_request);

  EXPECT_CALL(*mock_request_encoder_, encode(_, _))
      .WillOnce(Invoke([&](const Request&, RequestEncoderCallback& callback) -> void {
        Buffer::OwnedImpl buffer;
        buffer.add("hello");
        // Expect response.
        callback.onEncodingSuccess(buffer);
      }));

  if (with_tracing_) {
    // Inject tracing context.
    EXPECT_CALL(*child_span_, injectContext(_, _));
  }

  notifyPoolReady();

  EXPECT_NE(upstream_request->upstream_conn_, nullptr);

  if (with_tracing_) {
    EXPECT_CALL(*child_span_, setTag(_, _)).Times(testing::AnyNumber());
    EXPECT_CALL(*child_span_, finishSpan());
  }

  EXPECT_CALL(mock_filter_callback_, upstreamResponse(_, _))
      .WillOnce(Invoke([this](ResponsePtr, ExtendedOptions) {
        // When the response is sent to callback, the upstream request should be removed.
        EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
      }));

  auto response = std::make_unique<FakeStreamCodecFactory::FakeResponse>();
  notifyDecodingSuccess(std::move(response), ExtendedOptions());
}

TEST_P(RouterFilterTest, UpstreamRequestPoolReadyAndResponseWithDrainCloseSetInResponse) {
  ONLY_RUN_TEST_WITH_PARAM((TestParameters{false, false, false}));

  setup();
  kickOffNewUpstreamRequest();

  auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

  expectSetResponseCallback(upstream_request);

  EXPECT_CALL(*mock_request_encoder_, encode(_, _))
      .WillOnce(Invoke([&](const Request&, RequestEncoderCallback& callback) -> void {
        Buffer::OwnedImpl buffer;
        buffer.add("hello");
        // Expect response.
        callback.onEncodingSuccess(buffer);
      }));

  if (with_tracing_) {
    // Inject tracing context.
    EXPECT_CALL(*child_span_, injectContext(_, _));
  }

  notifyPoolReady();

  EXPECT_NE(upstream_request->upstream_conn_, nullptr);

  EXPECT_CALL(mock_filter_callback_, upstreamResponse(_, _))
      .WillOnce(Invoke([this](ResponsePtr, ExtendedOptions) {
        // When the response is sent to callback, the upstream request should be removed.
        EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
      }));

  EXPECT_CALL(mock_upstream_connection_, close(Network::ConnectionCloseType::FlushWrite));

  auto response = std::make_unique<FakeStreamCodecFactory::FakeResponse>();
  notifyDecodingSuccess(std::move(response), ExtendedOptions({}, false, true, false));
}

TEST_P(RouterFilterTest, UpstreamRequestPoolReadyAndResponseDecodingFailure) {
  setup();
  kickOffNewUpstreamRequest();

  auto upstream_request = filter_->upstreamRequestsForTest().begin()->get();

  expectSetResponseCallback(upstream_request);

  EXPECT_CALL(*mock_request_encoder_, encode(_, _))
      .WillOnce(Invoke([&](const Request&, RequestEncoderCallback& callback) -> void {
        Buffer::OwnedImpl buffer;
        buffer.add("hello");
        // Expect response.
        callback.onEncodingSuccess(buffer);
      }));

  notifyPoolReady();

  EXPECT_NE(upstream_request->upstream_conn_, nullptr);

  EXPECT_CALL(mock_filter_callback_, sendLocalReply(_, _))
      .WillOnce(Invoke([this](Status status, ResponseUpdateFunction&&) {
        EXPECT_EQ(0, filter_->upstreamRequestsForTest().size());
        EXPECT_EQ(status.message(), "protocol_error");
      }));

  expectConnectionClose();
  notifyDecodingFailure();
}

} // namespace
} // namespace Router
} // namespace GenericProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
