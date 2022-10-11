#include "config.h"

namespace Envoy {
namespace Extensions {
namespace CustomHandshaker {
namespace OpenSsl {

Ssl::HandshakerFactoryCb OpenSslHandshakerFactory::createHandshakerCb(
    const Protobuf::Message&, Ssl::HandshakerFactoryContext&, ProtobufMessage::ValidationVisitor&) {

  return [](bssl::UniquePtr<SSL> ssl, int ssl_extended_socket_info_index,
            Ssl::HandshakeCallbacks* handshake_callbacks) {
    return std::make_shared<OpenSslHandshakerImpl>(std::move(ssl), ssl_extended_socket_info_index,
                                                   handshake_callbacks);
  };
}

Ssl::SslCtxCb OpenSslHandshakerFactory::sslctxCb(Ssl::HandshakerFactoryContext&) const {
  return [](SSL_CTX* ssl_ctx) {
#ifndef OPENSSL_IS_BORINGSSL
    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ASYNC);
#else
    UNREFERENCED_PARAMETER(ssl_ctx);
#endif
  };
}

REGISTER_FACTORY(OpenSslHandshakerFactory, Ssl::HandshakerFactory);

} // namespace OpenSsl
} // namespace CustomHandshaker
} // namespace Extensions
} // namespace Envoy
