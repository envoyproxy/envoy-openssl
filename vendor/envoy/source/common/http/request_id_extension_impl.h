#pragma once

#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/http/request_id_extension.h"
#include "envoy/server/request_id_extension_config.h"

namespace Envoy {
namespace Http {
/**
 * Request ID Utilities factory that reads the configuration from proto.
 */
class RequestIDExtensionFactory {
public:
  /**
   * Read a RequestIDExtension definition from proto and create it.
   */
  static RequestIDExtensionSharedPtr fromProto(
      const envoy::extensions::filters::network::http_connection_manager::v3::RequestIDExtension&
          config,
      Server::Configuration::CommonFactoryContext& context);
};

} // namespace Http
} // namespace Envoy
