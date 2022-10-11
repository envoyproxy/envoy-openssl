#pragma once

#include <openssl/ssl3.h>

#include "envoy/network/transport_socket.h"

#include "source/extensions/transport_sockets/tls/ssl_handshaker.h"
#include "source/extensions/transport_sockets/tls/ssl_socket.h"
#include "source/extensions/transport_sockets/tls/utility.h"

namespace Envoy {
namespace Extensions {
namespace CustomHandshaker {
namespace OpenSsl {

class OpenSslHandshakerImpl : public TransportSockets::Tls::SslHandshakerImpl {
public:
  OpenSslHandshakerImpl(bssl::UniquePtr<SSL> ssl_ptr, int ssl_extended_socket_info_index,
                        Ssl::HandshakeCallbacks* handshake_callbacks)
      : TransportSockets::Tls::SslHandshakerImpl(std::move(ssl_ptr), ssl_extended_socket_info_index,
                                                 handshake_callbacks) {}

  Network::PostIoAction doHandshake() override;

private:
  void asyncCb(int fd);
  Network::PostIoAction doHandshake(bool from_async);

  mutable Event::FileEventPtr file_event_;
};

} // namespace OpenSsl
} // namespace CustomHandshaker
} // namespace Extensions
} // namespace Envoy
