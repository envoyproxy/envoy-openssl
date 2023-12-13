#include "source/extensions/transport_sockets/tls/context_manager_impl.h"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <limits>

#include "envoy/stats/scope.h"

#include "source/common/common/assert.h"
#include "source/extensions/transport_sockets/tls/context_impl.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

ContextManagerImpl::ContextManagerImpl(TimeSource& time_source) : time_source_(time_source) {}

Envoy::Ssl::ClientContextSharedPtr
ContextManagerImpl::createSslClientContext(Stats::Scope& scope,
                                           const Envoy::Ssl::ClientContextConfig& config) {
  if (!config.isReady()) {
    return nullptr;
  }

  Envoy::Ssl::ClientContextSharedPtr context =
      std::make_shared<ClientContextImpl>(scope, config, time_source_);
  contexts_.insert(context);
  return context;
}

Envoy::Ssl::ServerContextSharedPtr
ContextManagerImpl::createSslServerContext(Stats::Scope& scope,
                                           const Envoy::Ssl::ServerContextConfig& config,
                                           const std::vector<std::string>& server_names) {
  if (!config.isReady()) {
    return nullptr;
  }

  Envoy::Ssl::ServerContextSharedPtr context =
      std::make_shared<ServerContextImpl>(scope, config, server_names, time_source_);
  contexts_.insert(context);
  return context;
}

absl::optional<uint32_t> ContextManagerImpl::daysUntilFirstCertExpires() const {
  absl::optional<uint32_t> ret = absl::make_optional(std::numeric_limits<uint32_t>::max());
  for (const auto& context : contexts_) {
    if (context) {
      const absl::optional<uint32_t> tmp = context->daysUntilFirstCertExpires();
      if (!tmp.has_value()) {
        return absl::nullopt;
      }
      ret = std::min<uint32_t>(tmp.value(), ret.value());
    }
  }
  return ret;
}

absl::optional<uint64_t> ContextManagerImpl::secondsUntilFirstOcspResponseExpires() const {
  absl::optional<uint64_t> ret;
  for (const auto& context : contexts_) {
    if (context) {
      auto next_expiration = context->secondsUntilFirstOcspResponseExpires();
      if (next_expiration) {
        ret = std::min<uint64_t>(next_expiration.value(),
                                 ret.value_or(std::numeric_limits<uint64_t>::max()));
      }
    }
  }
  return ret;
}

void ContextManagerImpl::iterateContexts(std::function<void(const Envoy::Ssl::Context&)> callback) {
  for (const auto& context : contexts_) {
    if (context) {
      callback(*context);
    }
  }
}

void ContextManagerImpl::removeContext(const Envoy::Ssl::ContextSharedPtr& old_context) {
  if (old_context != nullptr) {
    auto erased = contexts_.erase(old_context);
    // The contexts is expected to be added before is removed.
    // And the prod ssl factory implementation guarantees any context is removed exactly once.
    ASSERT(erased == 1);
  }
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
