#include "openssl_handshaker.h"

namespace Envoy {
namespace Extensions {
namespace CustomHandshaker {
namespace OpenSsl {

void OpenSslHandshakerImpl::asyncCb(int fd) {
  ENVOY_CONN_LOG(debug, "SSL async done for fd {}", handshakeCallbacks()->connection(), fd);
  ASSERT(state() != Ssl::SocketState::PreHandshake);
  ASSERT(handshakeCallbacks()->connection().dispatcher().isThreadSafe());

  if (state() == Ssl::SocketState::ShutdownSent || state() == Ssl::SocketState::HandshakeComplete) {
    return;
  }

  Network::PostIoAction action = doHandshake(true);

  if (action == Network::PostIoAction::Close) {
    ENVOY_CONN_LOG(debug, "async handshake completion error", handshakeCallbacks()->connection());
    handshakeCallbacks()->connection().close(Network::ConnectionCloseType::FlushWrite);
    return;
  }
}

Network::PostIoAction OpenSslHandshakerImpl::doHandshake(bool from_async) {
  ASSERT(state() != Ssl::SocketState::HandshakeComplete &&
         state() != Ssl::SocketState::ShutdownSent);
  int rc = SSL_do_handshake(ssl());
  if (rc == 1) {
    ENVOY_CONN_LOG(debug, "handshake complete", handshakeCallbacks()->connection());
    setState(Ssl::SocketState::HandshakeComplete);
    handshakeCallbacks()->onSuccess(ssl());

    // It's possible that we closed during the handshake callback.
    return handshakeCallbacks()->connection().state() == Network::Connection::State::Open
               ? Network::PostIoAction::KeepOpen
               : Network::PostIoAction::Close;
  } else {
#ifdef OPENSSL_IS_BORINGSSL
    UNREFERENCED_PARAMETER(from_async);
#endif
    int err = SSL_get_error(ssl(), rc);
    ENVOY_CONN_LOG(trace, "ssl error occurred while read: {}", handshakeCallbacks()->connection(),
                   TransportSockets::Tls::Utility::getErrorDescription(err));
    switch (err) {
    case SSL_ERROR_WANT_READ:
      // TODO: This means that we need to wait for the socket to become readable/writable and
      // then try again. The waiting should be done in Envoy event loop also in the async case.
      ENVOY_CONN_LOG(debug, "SSL_ERROR_WANT_READ", handshakeCallbacks()->connection());
      return Network::PostIoAction::KeepOpen;
    case SSL_ERROR_WANT_WRITE:
      ENVOY_CONN_LOG(debug, "SSL_ERROR_WANT_WRITE", handshakeCallbacks()->connection());
      return Network::PostIoAction::KeepOpen;
#ifndef OPENSSL_IS_BORINGSSL
    case SSL_ERROR_WANT_ASYNC:
      int fd;
      OSSL_ASYNC_FD* fds;
      size_t numfds;
      ENVOY_CONN_LOG(debug, "SSL_ERROR_WANT_ASYNC", handshakeCallbacks()->connection());

      if (state() == Ssl::SocketState::HandshakeInProgress && !fromAsync) {
        // There's an ongoing async handshake going on and this call didn't
        // originate from the async call handler -- this is probably from another
        // source such as socket read or write calls. Don't start a new async
        // callback but instead just wait for the existing one to trigger.
        return Network::PostIoAction::KeepOpen;
      }

      setState(Ssl::SocketState::HandshakeInProgress);

      rc = SSL_get_all_async_fds(ssl(), NULL, &numfds);
      if (rc == 0) {
        handshakeCallbacks()->onFailure();
        return Network::PostIoAction::Close;
      }

      /* We only wait for the first fd here! Will fail if multiple async engines. */
      if (numfds != 1) {
        handshakeCallbacks()->onFailure();
        return Network::PostIoAction::Close;
      }

      fds = static_cast<OSSL_ASYNC_FD*>(malloc(numfds * sizeof(OSSL_ASYNC_FD)));
      if (fds == NULL) {
        handshakeCallbacks()->onFailure();
        return Network::PostIoAction::Close;
      }

      rc = SSL_get_all_async_fds(ssl(), fds, &numfds);
      if (rc == 0) {
        free(fds);
        handshakeCallbacks()->onFailure();
        return Network::PostIoAction::Close;
      }

      fd = fds[0];
      file_event_ = handshakeCallbacks()->connection().dispatcher().createFileEvent(
          fd, [this, fd](uint32_t /* events */) -> void { asyncCb(fd); },
          Event::FileTriggerType::Edge, Event::FileReadyType::Read);

      ENVOY_CONN_LOG(debug, "SSL async fd: {}, numfds: {}", handshakeCallbacks()->connection(), fd,
                     numfds);
      free(fds);

      return Network::PostIoAction::KeepOpen;
#endif
    case SSL_ERROR_WANT_CERTIFICATE_VERIFY:
      setState(Ssl::SocketState::HandshakeInProgress);
      return Network::PostIoAction::KeepOpen;
    default:
      ENVOY_CONN_LOG(debug, "handshake error: {}", handshakeCallbacks()->connection(), err);
      setState(Ssl::SocketState::HandshakeComplete);
      handshakeCallbacks()->onFailure();
      return Network::PostIoAction::Close;
    }
  }
}

Network::PostIoAction OpenSslHandshakerImpl::doHandshake() { return doHandshake(false); }

} // namespace OpenSsl
} // namespace CustomHandshaker
} // namespace Extensions
} // namespace Envoy
