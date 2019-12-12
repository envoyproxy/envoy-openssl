#pragma once

#include "envoy/config/filter/http/lua/v2/lua.pb.h"
#include "envoy/config/filter/http/lua/v2/lua.pb.validate.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Lua {

/**
 * Config registration for the Lua filter. @see NamedHttpFilterConfigFactory.
 */
class LuaFilterConfig : public Common::FactoryBase<envoy::config::filter::http::lua::v2::Lua> {
public:
  LuaFilterConfig() : FactoryBase(HttpFilterNames::get().Lua) {}

private:
  Http::FilterFactoryCb
  createFilterFactoryFromProtoTyped(const envoy::config::filter::http::lua::v2::Lua& proto_config,
                                    const std::string&,
                                    Server::Configuration::FactoryContext& context) override;
};

} // namespace Lua
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
