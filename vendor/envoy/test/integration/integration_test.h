#pragma once

#include "test/integration/http_integration.h"
#include "test/test_common/utility.h"

#include "gtest/gtest.h"

// A test class for testing HTTP/1.1 upstream and downstreams
namespace Envoy {
class IntegrationTest
    : public testing::TestWithParam<std::tuple<Network::Address::IpVersion, Http1ParserImpl>>,
      public HttpIntegrationTest {
public:
  IntegrationTest()
      : HttpIntegrationTest(Http::CodecType::HTTP1, std::get<0>(GetParam())),
        http1_implementation_(std::get<1>(GetParam())) {
    setupHttp1ImplOverrides(http1_implementation_);
  }

protected:
  const Http1ParserImpl http1_implementation_;
};

class UpstreamEndpointIntegrationTest
    : public testing::TestWithParam<std::tuple<Network::Address::IpVersion, Http1ParserImpl>>,
      public HttpIntegrationTest {
public:
  UpstreamEndpointIntegrationTest()
      : HttpIntegrationTest(
            Http::CodecType::HTTP1,
            [](int) {
              return Network::Utility::parseInternetAddress(
                  Network::Test::getLoopbackAddressString(std::get<0>(GetParam())), 0);
            },
            std::get<0>(GetParam())),
        http1_implementation_(std::get<1>(GetParam())) {
    setupHttp1ImplOverrides(http1_implementation_);
  }

protected:
  const Http1ParserImpl http1_implementation_;
};
} // namespace Envoy
