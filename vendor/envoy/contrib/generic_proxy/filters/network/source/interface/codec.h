#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/config/typed_config.h"
#include "envoy/network/filter.h"
#include "envoy/server/factory_context.h"

#include "contrib/generic_proxy/filters/network/source/interface/codec_callbacks.h"
#include "contrib/generic_proxy/filters/network/source/interface/stream.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace GenericProxy {

/**
 * Decoder of request.
 */
class RequestDecoder {
public:
  virtual ~RequestDecoder() = default;

  // The decode() method may be called multiple times for single request or response.
  // So an independent setDecoderCallback() is used to set decoding callback.
  virtual void setDecoderCallback(RequestDecoderCallback& callback) PURE;
  virtual void decode(Buffer::Instance& buffer) PURE;
};

/**
 * Decoder of response.
 */
class ResponseDecoder {
public:
  virtual ~ResponseDecoder() = default;

  // The decode() method may be called multiple times for single request or response.
  // So an independent setDecoderCallback() is used to set decoding callback.
  virtual void setDecoderCallback(ResponseDecoderCallback& callback) PURE;
  virtual void decode(Buffer::Instance& buffer) PURE;
};

/*
 * Encoder of request.
 */
class RequestEncoder {
public:
  virtual ~RequestEncoder() = default;

  virtual void encode(const Request&, RequestEncoderCallback& callback) PURE;
};

/*
 * Encoder of response.
 */
class ResponseEncoder {
public:
  virtual ~ResponseEncoder() = default;

  virtual void encode(const Response&, ResponseEncoderCallback& callback) PURE;
};

class MessageCreator {
public:
  virtual ~MessageCreator() = default;

  /**
   * Create local response message for local reply.
   */
  virtual ResponsePtr response(Status status, const Request& origin_request) PURE;
};

using RequestDecoderPtr = std::unique_ptr<RequestDecoder>;
using ResponseDecoderPtr = std::unique_ptr<ResponseDecoder>;
using RequestEncoderPtr = std::unique_ptr<RequestEncoder>;
using ResponseEncoderPtr = std::unique_ptr<ResponseEncoder>;
using MessageCreatorPtr = std::unique_ptr<MessageCreator>;

/**
 * Protocol specific options to control the behavior of the connection manager (generic proxy).
 */
class ProtocolOptions {
public:
  ProtocolOptions(bool bind_upstream_connection)
      : bind_upstream_connection_(bind_upstream_connection) {}
  ProtocolOptions() = default;

  /**
   * @return true if the upstream connection should be bound to the downstream connection, false
   * otherwise.
   *
   * By default, one random upstream connection will be selected from the upstream connection pool
   * and used for every request. And after the request is finished, the upstream connection will be
   * released back to the upstream connection pool.
   *
   * If this option is true, the upstream connection will be bound to the downstream connection and
   * have same lifetime as the downstream connection. The same upstream connection will be used for
   * all requests from the same downstream connection.
   *
   * And if this options is true, one of the following requirements must be met:
   * 1. The request must be handled one by one. That is, the next request can not be sent to the
   *    upstream until the previous request is finished.
   * 2. Unique request id must be provided for each request and response. The request id must be
   *    unique for each request and response pair in same connection pair. And the request id must
   *    be the same for the corresponding request and response.
   * TODO(wbpcode): add pipeline support in the future.
   *
   * This could be useful for some protocols that require the same upstream connection to be used
   * for all requests from the same downstream connection. For example, the protocol using stateful
   * connection.
   */
  bool bindUpstreamConnection() const { return bind_upstream_connection_; }

private:
  bool bind_upstream_connection_{false};
};

/**
 * Factory used to create generic stream encoder and decoder. If the developer wants to add
 * new protocol support to this proxy, they need to implement the corresponding codec factory for
 * the corresponding protocol.
 */
class CodecFactory {
public:
  virtual ~CodecFactory() = default;

  /*
   * Create request decoder.
   */
  virtual RequestDecoderPtr requestDecoder() const PURE;

  /*
   * Create response decoder.
   */
  virtual ResponseDecoderPtr responseDecoder() const PURE;

  /*
   * Create request encoder.
   */
  virtual RequestEncoderPtr requestEncoder() const PURE;

  /*
   * Create response encoder.
   */
  virtual ResponseEncoderPtr responseEncoder() const PURE;

  /**
   * Create message creator.
   */
  virtual MessageCreatorPtr messageCreator() const PURE;

  /**
   * @return the options to control the behavior of generic proxy filter.
   */
  virtual ProtocolOptions protocolOptions() const PURE;
};

using CodecFactoryPtr = std::unique_ptr<CodecFactory>;

class FilterConfig;
using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

/**
 * Custom read filter factory for generic proxy.
 */
class ProxyFactory {
public:
  virtual ~ProxyFactory() = default;

  /**
   * Create a custom proxy instance.
   * @param filter_manager the filter manager of the network filter chain.
   * @param filter_config supplies the read filter config.
   */
  virtual void createProxy(Network::FilterManager& filter_manager,
                           const FilterConfigSharedPtr& filter_config) const PURE;
};
using ProxyFactoryPtr = std::unique_ptr<ProxyFactory>;

/**
 * Factory config for codec factory. This class is used to register and create codec factories.
 */
class CodecFactoryConfig : public Envoy::Config::TypedFactory {
public:
  /**
   * Create a codec factory. This should never return nullptr.
   * @param config supplies the config.
   * @param context supplies the server context.
   * @return CodecFactoryPtr the codec factory.
   */
  virtual CodecFactoryPtr createCodecFactory(const Protobuf::Message&,
                                             Envoy::Server::Configuration::FactoryContext&) PURE;

  /**
   * Create a optional custom proxy factory.
   * @param config supplies the config.
   * @param context supplies the server context.
   * @return ProxyFactoryPtr the proxy factory to create generic proxy instance or nullptr if no
   * custom proxy is needed and the default generic proxy will be used.
   */
  virtual ProxyFactoryPtr createProxyFactory(const Protobuf::Message&,
                                             Envoy::Server::Configuration::FactoryContext&) {
    return nullptr;
  }

  std::string category() const override { return "envoy.generic_proxy.codecs"; }
};

} // namespace GenericProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
