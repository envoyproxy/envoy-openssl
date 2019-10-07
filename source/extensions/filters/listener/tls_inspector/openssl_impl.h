#pragma once

#include <functional>
#include <string>
#include <vector>

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {

const SSL_METHOD* TLS_with_buffers_method();

void set_certificate_cb(SSL_CTX* ctx);

std::vector<absl::string_view> getAlpnProtocols(const unsigned char* data, unsigned int len);
int getServernameCallbackReturn(int* out_alert);

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
