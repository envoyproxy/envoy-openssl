#pragma once

#include <openssl/ssl3.h>

#include "envoy/ssl/handshaker.h"

#include "source/common/common/logger.h"
#include "source/extensions/transport_sockets/tls/ssl_handshaker.h"

#include "openssl_handshaker.h"

namespace Envoy {
namespace Extensions {
namespace CustomHandshaker {
namespace OpenSsl {

class OpenSslHandshakerFactory : public Extensions::TransportSockets::Tls::HandshakerFactoryImpl,
                                 public Logger::Loggable<Logger::Id::connection> {
public:
  Ssl::HandshakerFactoryCb createHandshakerCb(const Protobuf::Message&,
                                              Ssl::HandshakerFactoryContext&,
                                              ProtobufMessage::ValidationVisitor&) override;

  Ssl::SslCtxCb sslctxCb(Ssl::HandshakerFactoryContext& handshaker_factory_context) const override;

  static constexpr char kFactoryName[] = "envoy.tls_handshakers.openssl";
  std::string name() const override { return kFactoryName; }
};

} // namespace OpenSsl
} // namespace CustomHandshaker
} // namespace Extensions
} // namespace Envoy
