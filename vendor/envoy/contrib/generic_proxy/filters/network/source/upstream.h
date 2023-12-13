#pragma once

#include <memory>

#include "envoy/network/connection.h"
#include "envoy/upstream/thread_local_cluster.h"

#include "contrib/generic_proxy/filters/network/source/interface/codec.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace GenericProxy {

class UpstreamConnection : public Envoy::Event::DeferredDeletable,
                           public Tcp::ConnectionPool::Callbacks,
                           public Tcp::ConnectionPool::UpstreamCallbacks,
                           public Envoy::Logger::Loggable<Envoy::Logger::Id::upstream> {
public:
  ~UpstreamConnection() override;

  void newConnection() { tcp_pool_handle_ = tcp_pool_data_.newConnection(*this); }

  void cleanUp(bool close_connection);

  // Tcp::ConnectionPool::Callbacks
  void onPoolFailure(ConnectionPool::PoolFailureReason, absl::string_view,
                     Upstream::HostDescriptionConstSharedPtr) override;
  void onPoolReady(Tcp::ConnectionPool::ConnectionDataPtr&& conn_data,
                   Upstream::HostDescriptionConstSharedPtr host) override;

  // Tcp::ConnectionPool::UpstreamCallbacks
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}
  void onUpstreamData(Buffer::Instance& data, bool end_stream) override;
  void onEvent(Network::ConnectionEvent) override;

protected:
  UpstreamConnection(Upstream::TcpPoolData&& tcp_pool_data, ResponseDecoderPtr&& response_decoder)
      : tcp_pool_data_(std::move(tcp_pool_data)), response_decoder_(std::move(response_decoder)) {}

  virtual void onEventImpl(Network::ConnectionEvent event) PURE;
  virtual void onPoolSuccessImpl() PURE;
  virtual void onPoolFailureImpl(ConnectionPool::PoolFailureReason reason,
                                 absl::string_view transport_failure_reason) PURE;

  Upstream::TcpPoolData tcp_pool_data_;
  ResponseDecoderPtr response_decoder_;

  bool is_cleaned_up_{};

  Tcp::ConnectionPool::Cancellable* tcp_pool_handle_{};
  Tcp::ConnectionPool::ConnectionDataPtr owned_conn_data_;
  Upstream::HostDescriptionConstSharedPtr upstream_host_;
};

} // namespace GenericProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
