#pragma once

#include "envoy/common/random_generator.h"
#include "envoy/runtime/runtime.h"

#include "source/common/common/interval_value.h"

#include "absl/strings/string_view.h"
#include "base_listener_impl.h"

namespace Envoy {
namespace Network {

/**
 * libevent implementation of Network::Listener for TCP.
 */
class TcpListenerImpl : public BaseListenerImpl {
public:
  TcpListenerImpl(Event::DispatcherImpl& dispatcher, Random::RandomGenerator& random,
                  Runtime::Loader& runtime, SocketSharedPtr socket, TcpListenerCallbacks& cb,
                  bool bind_to_port, bool ignore_global_conn_limit);
  ~TcpListenerImpl() override {
    if (bind_to_port_) {
      socket_->ioHandle().resetFileEvents();
    }
  }
  void disable() override;
  void enable() override;
  void setRejectFraction(UnitFloat reject_fraction) override;
  void configureLoadShedPoints(Server::LoadShedPointProvider& load_shed_point_provider) override;

  static const absl::string_view GlobalMaxCxRuntimeKey;

protected:
  TcpListenerCallbacks& cb_;

private:
  void onSocketEvent(short flags);

  // Returns true if global connection limit has been reached and the accepted socket should be
  // rejected/closed. If the accepted socket is to be admitted, false is returned.
  bool rejectCxOverGlobalLimit() const;

  Random::RandomGenerator& random_;
  Runtime::Loader& runtime_;
  bool bind_to_port_;
  UnitFloat reject_fraction_;
  const bool ignore_global_conn_limit_;
  Server::LoadShedPoint* listener_accept_{nullptr};
};

} // namespace Network
} // namespace Envoy
