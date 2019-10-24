#include "extensions/filters/listener/tls_inspector/tls_inspector.h"

#include <arpa/inet.h>

#include <cstdint>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/scope.h"

#include "common/api/os_sys_calls_impl.h"
#include "common/common/assert.h"

#include "extensions/filters/listener/tls_inspector/openssl_impl.h"
#include "extensions/transport_sockets/well_known_names.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {

Config::Config(Stats::Scope& scope, uint32_t max_client_hello_size)
    : stats_{ALL_TLS_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, "tls_inspector."))},
      ssl_ctx_(
          SSL_CTX_new(Envoy::Extensions::ListenerFilters::TlsInspector::TLS_with_buffers_method())),
      max_client_hello_size_(max_client_hello_size) {
  if (max_client_hello_size_ > TLS_MAX_CLIENT_HELLO) {
    throw EnvoyException(fmt::format("max_client_hello_size of {} is greater than maximum of {}.",
                                     max_client_hello_size_, size_t(TLS_MAX_CLIENT_HELLO)));
  }

  SSL_CTX_set_options(ssl_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(ssl_ctx_.get(), SSL_SESS_CACHE_OFF);

  Envoy::Extensions::ListenerFilters::TlsInspector::set_certificate_cb(ssl_ctx_.get());

  auto tlsext_servername_cb = +[](SSL* ssl, int* out_alert, void*) -> int {
    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
    absl::string_view servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    filter->onServername(servername);
    if (servername.rfind("outbound_") != std::string::npos) {
      filter->setIstioApplicationProtocol();
    }

    return Envoy::Extensions::ListenerFilters::TlsInspector::getServernameCallbackReturn(out_alert);
  };
  SSL_CTX_set_tlsext_servername_callback(ssl_ctx_.get(), tlsext_servername_cb);

  auto alpn_cb = [](SSL* ssl, const unsigned char**, unsigned char*,
                    const unsigned char* in, unsigned int inlen, void*) -> int {
    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
    filter->onALPN(in, inlen);

    return SSL_TLSEXT_ERR_OK;
  };
  SSL_CTX_set_alpn_select_cb(ssl_ctx_.get(), alpn_cb, nullptr);

  auto cert_cb = [](SSL* ssl, void*) -> int {
    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
    filter->onCert();    

    return SSL_TLSEXT_ERR_OK;
  };
  SSL_CTX_set_cert_cb(ssl_ctx_.get(), cert_cb, nullptr);

}

bssl::UniquePtr<SSL> Config::newSsl() { return bssl::UniquePtr<SSL>{SSL_new(ssl_ctx_.get())}; }

thread_local uint8_t Filter::buf_[Config::TLS_MAX_CLIENT_HELLO];

Filter::Filter(const ConfigSharedPtr config) : config_(config), ssl_(config_->newSsl()) {
  RELEASE_ASSERT(sizeof(buf_) >= config_->maxClientHelloSize(), "");

  SSL_set_app_data(ssl_.get(), this);
  SSL_set_accept_state(ssl_.get());
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(debug, "tls inspector: new connection accepted");
  Network::ConnectionSocket& socket = cb.socket();
  ASSERT(file_event_ == nullptr);
  cb_ = &cb;

  ParseState parse_state = onRead();
  switch (parse_state) {
  case ParseState::Error:
    // As per discussion in https://github.com/envoyproxy/envoy/issues/7864
    // we don't add new enum in FilterStatus so we have to signal the caller
    // the new condition.
    cb.socket().close();
    return Network::FilterStatus::StopIteration;
  case ParseState::Done:
    return Network::FilterStatus::Continue;
  case ParseState::Continue:
    // do nothing but create the event
    file_event_ = cb.dispatcher().createFileEvent(
        socket.ioHandle().fd(),
        [this](uint32_t events) {
          if (events & Event::FileReadyType::Closed) {
            config_->stats().connection_closed_.inc();
            done(false);
            return;
          }

          ASSERT(events == Event::FileReadyType::Read);
          ParseState parse_state = onRead();
          switch (parse_state) {
          case ParseState::Error:
            done(false);
            break;
          case ParseState::Done:
            done(true);
            break;
          case ParseState::Continue:
            // do nothing but wait for the next event
            break;
          }
        },
        Event::FileTriggerType::Edge, Event::FileReadyType::Read | Event::FileReadyType::Closed);
    return Network::FilterStatus::StopIteration;
  }
  NOT_REACHED_GCOVR_EXCL_LINE;
}

void Filter::onALPN(const unsigned char* data, unsigned int len) {
  std::vector<absl::string_view> protocols =
      Envoy::Extensions::ListenerFilters::TlsInspector::getAlpnProtocols(data, len);
  cb_->socket().setRequestedApplicationProtocols(protocols);
  alpn_found_ = true;
}

void Filter::onCert() {
  std::vector<absl::string_view> protocols;
  if (istio_protocol_required_) {
    protocols.emplace_back("istio");
  }
  cb_->socket().setRequestedApplicationProtocols(protocols);
}

void Filter::onServername(absl::string_view name) {
  if (!name.empty()) {
    config_->stats().sni_found_.inc();
    cb_->socket().setRequestedServerName(name);
    ENVOY_LOG(debug, "tls:onServerName(), requestedServerName: {}", name);
  } else {
    config_->stats().sni_not_found_.inc();
  }
  clienthello_success_ = true;
}

void Filter::setIstioApplicationProtocol() {
  istio_protocol_required_ = true;
}

ParseState Filter::onRead() {
  // This receive code is somewhat complicated, because it must be done as a MSG_PEEK because
  // there is no way for a listener-filter to pass payload data to the ConnectionImpl and filters
  // that get created later.
  //
  // The file_event_ in this class gets events every time new data is available on the socket,
  // even if previous data has not been read, which is always the case due to MSG_PEEK. When
  // the TlsInspector completes and passes the socket along, a new FileEvent is created for the
  // socket, so that new event is immediately signaled as readable because it is new and the socket
  // is readable, even though no new events have occurred.
  //
  // TODO(ggreenway): write an integration test to ensure the events work as expected on all
  // platforms.
  auto& os_syscalls = Api::OsSysCallsSingleton::get();
  const Api::SysCallSizeResult result = os_syscalls.recv(cb_->socket().ioHandle().fd(), buf_,
                                                         config_->maxClientHelloSize(), MSG_PEEK);
  ENVOY_LOG(trace, "tls inspector: recv: {}", result.rc_);

  if (result.rc_ == -1 && result.errno_ == EAGAIN) {
    return ParseState::Continue;
  } else if (result.rc_ < 0) {
    config_->stats().read_error_.inc();
    return ParseState::Error;
  }

  // Because we're doing a MSG_PEEK, data we've seen before gets returned every time, so
  // skip over what we've already processed.
  if (static_cast<uint64_t>(result.rc_) > read_) {
    const uint8_t* data = buf_ + read_;
    const size_t len = result.rc_ - read_;
    read_ = result.rc_;
    return parseClientHello(data, len);
  }
  return ParseState::Continue;
}

void Filter::done(bool success) {
  ENVOY_LOG(trace, "tls inspector: done: {}", success);
  file_event_.reset();
  cb_->continueFilterChain(success);
}

ParseState Filter::parseClientHello(const void* data, size_t len) {
  // Ownership is passed to ssl_ in SSL_set_bio()
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data, len));

  // Make the mem-BIO return that there is more data
  // available beyond it's end
  BIO_set_mem_eof_return(bio.get(), -1);

  SSL_set_bio(ssl_.get(), bio.get(), bio.get());
  bio.release();

  int ret = SSL_do_handshake(ssl_.get());

  // This should never succeed because an error is always returned from the SNI callback.
  ASSERT(ret <= 0);
  switch (SSL_get_error(ssl_.get(), ret)) {
  case SSL_ERROR_WANT_READ:
    if (read_ == config_->maxClientHelloSize()) {
      // We've hit the specified size limit. This is an unreasonably large ClientHello;
      // indicate failure.
      config_->stats().client_hello_too_large_.inc();
      return ParseState::Error;
    }
    return ParseState::Continue;
  case SSL_ERROR_SSL:
    if (clienthello_success_) {
      config_->stats().tls_found_.inc();
      if (alpn_found_) {
        config_->stats().alpn_found_.inc();
      } else {
        config_->stats().alpn_not_found_.inc();
      }
      cb_->socket().setDetectedTransportProtocol(
          TransportSockets::TransportProtocolNames::get().Tls);
    } else {
      config_->stats().tls_not_found_.inc();
    }
    return ParseState::Done;
  default:
    return ParseState::Error;
  }
}

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
