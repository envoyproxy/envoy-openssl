#include "source/common/config/datasource.h"

#include "envoy/config/core/v3/base.pb.h"

#include "source/common/config/utility.h"

#include "fmt/format.h"

namespace Envoy {
namespace Config {
namespace DataSource {

// Default Parameters of the jittered backoff strategy.
static constexpr uint32_t RetryInitialDelayMilliseconds = 1000;
static constexpr uint32_t RetryMaxDelayMilliseconds = 10 * 1000;
static constexpr uint32_t RetryCount = 1;

std::string read(const envoy::config::core::v3::DataSource& source, bool allow_empty,
                 Api::Api& api) {
  std::string data;
  switch (source.specifier_case()) {
  case envoy::config::core::v3::DataSource::SpecifierCase::kFilename:
    data = api.fileSystem().fileReadToEnd(source.filename());
    break;
  case envoy::config::core::v3::DataSource::SpecifierCase::kInlineBytes:
    data = source.inline_bytes();
    break;
  case envoy::config::core::v3::DataSource::SpecifierCase::kInlineString:
    data = source.inline_string();
    break;
  case envoy::config::core::v3::DataSource::SpecifierCase::kEnvironmentVariable: {
    const char* environment_variable = std::getenv(source.environment_variable().c_str());
    if (environment_variable == nullptr) {
      throw EnvoyException(
          fmt::format("Environment variable doesn't exist: {}", source.environment_variable()));
    }
    data = environment_variable;
    break;
  }
  default:
    if (!allow_empty) {
      throw EnvoyException(
          fmt::format("Unexpected DataSource::specifier_case(): {}", source.specifier_case()));
    }
  }
  if (!allow_empty && data.empty()) {
    throw EnvoyException("DataSource cannot be empty");
  }
  return data;
}

absl::optional<std::string> getPath(const envoy::config::core::v3::DataSource& source) {
  return source.specifier_case() == envoy::config::core::v3::DataSource::SpecifierCase::kFilename
             ? absl::make_optional(source.filename())
             : absl::nullopt;
}

RemoteAsyncDataProvider::RemoteAsyncDataProvider(
    Upstream::ClusterManager& cm, Init::Manager& manager,
    const envoy::config::core::v3::RemoteDataSource& source, Event::Dispatcher& dispatcher,
    Random::RandomGenerator& random, bool allow_empty, AsyncDataSourceCb&& callback)
    : allow_empty_(allow_empty), callback_(std::move(callback)),
      fetcher_(std::make_unique<Config::DataFetcher::RemoteDataFetcher>(cm, source.http_uri(),
                                                                        source.sha256(), *this)),
      init_target_("RemoteAsyncDataProvider", [this]() { start(); }),
      retries_remaining_(
          PROTOBUF_GET_WRAPPED_OR_DEFAULT(source.retry_policy(), num_retries, RetryCount)) {

  backoff_strategy_ = Utility::prepareJitteredExponentialBackOffStrategy(
      source, random, RetryInitialDelayMilliseconds, RetryMaxDelayMilliseconds);

  retry_timer_ = dispatcher.createTimer([this]() -> void { start(); });

  manager.add(init_target_);
}

} // namespace DataSource
} // namespace Config
} // namespace Envoy
