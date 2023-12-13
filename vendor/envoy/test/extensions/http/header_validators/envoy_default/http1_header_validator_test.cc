#include "envoy/http/header_validator_errors.h"

#include "source/extensions/http/header_validators/envoy_default/http1_header_validator.h"

#include "test/extensions/http/header_validators/envoy_default/header_validator_test.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

namespace Envoy {
namespace Extensions {
namespace Http {
namespace HeaderValidators {
namespace EnvoyDefault {
namespace {

using ::Envoy::Http::HeaderString;
using ::Envoy::Http::LowerCaseString;
using ::Envoy::Http::Protocol;
using ::Envoy::Http::TestRequestHeaderMapImpl;
using ::Envoy::Http::TestRequestTrailerMapImpl;
using ::Envoy::Http::TestResponseHeaderMapImpl;
using ::Envoy::Http::UhvResponseCodeDetail;

class Http1HeaderValidatorTest : public HeaderValidatorTest {
protected:
  Http1HeaderValidatorPtr createH1(absl::string_view config_yaml) {
    envoy::extensions::http::header_validators::envoy_default::v3::HeaderValidatorConfig
        typed_config;
    TestUtility::loadFromYaml(std::string(config_yaml), typed_config);

    return std::make_unique<Http1HeaderValidator>(typed_config, Protocol::Http11, stats_);
  }

  TestRequestHeaderMapImpl makeGoodRequestHeaders() {
    return TestRequestHeaderMapImpl{
        {":method", "GET"}, {":authority", "envoy.com"}, {":path", "/"}};
  }

  TestResponseHeaderMapImpl makeGoodResponseHeaders() {
    return TestResponseHeaderMapImpl{{":status", "200"}};
  }

  TestScopedRuntime scoped_runtime_;
};

TEST_F(Http1HeaderValidatorTest, GoodHeadersAccepted) {
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(request_headers));
  TestResponseHeaderMapImpl response_headers = makeGoodResponseHeaders();
  EXPECT_ACCEPT(uhv->validateResponseHeaderMap(response_headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateTransferEncodingInRequest) {
  auto uhv = createH1(empty_config);

  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  request_headers.setCopy(LowerCaseString("transfer-encoding"), "ChuNKeD");
  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(request_headers));

  request_headers.setCopy(LowerCaseString("transfer-encoding"), "gzip");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(request_headers),
                             "uhv.http1.invalid_transfer_encoding");
}

TEST_F(Http1HeaderValidatorTest, ValidateTransferEncodingInResponse) {
  auto uhv = createH1(empty_config);

  TestResponseHeaderMapImpl request_headers = makeGoodResponseHeaders();
  request_headers.setCopy(LowerCaseString("transfer-encoding"), "ChuNKeD");
  EXPECT_ACCEPT(uhv->validateResponseHeaderMap(request_headers));

  request_headers.setCopy(LowerCaseString("transfer-encoding"), "gzip");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(request_headers),
                             "uhv.http1.invalid_transfer_encoding");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderEntryCustomMethod) {
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  request_headers.setMethod("CUSTOM-METHOD");
  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(request_headers));
}

TEST_F(Http1HeaderValidatorTest, AuthorityWithUserInfoRejected) {
  // TODO(yanavlasov): check if this restriction is applied to H/1 protocol
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  request_headers.setHost("user:pass@envoy.com");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(request_headers),
                             UhvResponseCodeDetail::get().InvalidHostDeprecatedUserInfo);
}

TEST_F(Http1HeaderValidatorTest, InvalidSchemeRejected) {
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  request_headers.setScheme("http_ssh");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(request_headers),
                             UhvResponseCodeDetail::get().InvalidScheme);
}

TEST_F(Http1HeaderValidatorTest, InvalidPathIsRejected) {
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  request_headers.setPath("/ bad path");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(request_headers),
                             UhvResponseCodeDetail::get().InvalidUrl);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestContentLength) {
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  request_headers.setContentLength("100");
  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(request_headers));

  request_headers.setContentLength("10a2");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(request_headers),
                             UhvResponseCodeDetail::get().InvalidContentLength);
}

TEST_F(Http1HeaderValidatorTest, InvalidRequestHeaderNameRejected) {
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  // This header name is valid
  request_headers.addCopy("x-foo", "bar");
  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(request_headers));

  // Reject invalid name
  request_headers.addCopy("foo oo", "bar");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(request_headers),
                             UhvResponseCodeDetail::get().InvalidNameCharacters);
}

TEST_F(Http1HeaderValidatorTest, InvalidRequestHeaderValueRejected) {
  auto uhv = createH1(empty_config);
  TestRequestHeaderMapImpl request_headers = makeGoodRequestHeaders();
  HeaderString invalid_value{};
  setHeaderStringUnvalidated(invalid_value, "hello\nworld");
  request_headers.addViaMove(HeaderString(absl::string_view("x-foo")), std::move(invalid_value));
  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(request_headers),
                             UhvResponseCodeDetail::get().InvalidValueCharacters);
}

TEST_F(Http1HeaderValidatorTest, InvalidResponseHeaderNameRejected) {
  auto uhv = createH1(empty_config);
  TestResponseHeaderMapImpl response_headers = makeGoodResponseHeaders();
  // This header name is valid
  response_headers.addCopy("x-foo", "bar");
  EXPECT_ACCEPT(uhv->validateResponseHeaderMap(response_headers));

  // Reject invalid name
  response_headers.addCopy("foo oo", "bar");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(response_headers),
                             UhvResponseCodeDetail::get().InvalidNameCharacters);
}

TEST_F(Http1HeaderValidatorTest, InvalidResponseHeaderValueRejected) {

  auto uhv = createH1(empty_config);
  TestResponseHeaderMapImpl response_headers = makeGoodResponseHeaders();
  HeaderString invalid_value{};
  setHeaderStringUnvalidated(invalid_value, "hello\nworld");
  response_headers.addViaMove(HeaderString(absl::string_view("x-foo")), std::move(invalid_value));
  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(response_headers),
                             UhvResponseCodeDetail::get().InvalidValueCharacters);
}

TEST_F(Http1HeaderValidatorTest, InvalidResponseStatusRejected) {
  auto uhv = createH1(empty_config);
  TestResponseHeaderMapImpl response_headers = makeGoodResponseHeaders();
  response_headers.setStatus("1024");
  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(response_headers),
                             UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapAllowed) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapAllowedHostAlias) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {"host", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapMissingPath) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "GET"}, {":authority", "envoy.com"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidUrl);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapMissingMethod) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":path", "/"}, {":authority", "envoy.com"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidMethod);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapMissingHost) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "GET"}, {":path", "/"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapStarPathAccept) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "OPTIONS"},
                                                  {":path", "*"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapStarPathReject) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "*"},
                                                  {":authority", "envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidUrl);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingValid) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateConnectRegName) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "www.envoy.com:443"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateConnectIPv6) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "[2001:8080]:9000"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateConnectInvalidUserInfo) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "user:pass@envoy.com"},
                                                  {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidHostDeprecatedUserInfo);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingConnect) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             "uhv.http1.transfer_encoding_not_allowed");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingContentLengthReject) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"},
                                                  {"content-length", "10"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             "http1.content_length_and_chunked_not_allowed");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapTransferEncodingContentLengthAllow) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"transfer-encoding", "chunked"},
                                                  {"content-length", "10"}};
  auto uhv = createH1(allow_chunked_length_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
  EXPECT_EQ(headers.ContentLength(), nullptr);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapContentLengthNoTransferEncoding) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"content-length", "10"}};
  auto uhv = createH1(allow_chunked_length_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
  EXPECT_EQ(headers.getContentLengthValue(), "10");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapContentLengthConnectReject) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "envoy.com:80"},
                                                  {"content-length", "10"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             "uhv.http1.content_length_not_allowed");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapConnectRegNameMissingPort) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "CONNECT"}, {":authority", "envoy.com"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapConnectIPv6MissingPort) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "CONNECT"}, {":authority", "[2001:8080]"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidHost);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapContentLength0ConnectAccept) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "envoy.com:80"},
                                                  {"content-length", "0"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
  EXPECT_EQ(headers.ContentLength(), nullptr);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapConnectWithPath) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "CONNECT"}, {":authority", "envoy.com:80"}, {":path", "/"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidUrl);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapExtraPseudo) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "envoy.com:80"},
                                                  {":status", "200"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidPseudoHeader);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapEmptyGeneric) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "CONNECT"}, {":authority", "envoy.com:80"}, {"", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().EmptyHeaderName);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapInvalidGeneric) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "CONNECT"},
                                                  {":authority", "envoy.com:80"},
                                                  {"foo header", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidNameCharacters);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapUnderscoreHeadersAllowedByDefault) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"x_foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
  EXPECT_EQ(headers, ::Envoy::Http::TestRequestHeaderMapImpl({{":scheme", "https"},
                                                              {":method", "GET"},
                                                              {":path", "/"},
                                                              {":authority", "envoy.com"},
                                                              {"x_foo", "bar"}}));
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapDropUnderscoreHeaders) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"x_foo", "bar"}};
  auto uhv = createH1(drop_headers_with_underscores_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
  EXPECT_EQ(
      headers,
      ::Envoy::Http::TestRequestHeaderMapImpl(
          {{":scheme", "https"}, {":method", "GET"}, {":path", "/"}, {":authority", "envoy.com"}}));
}

TEST_F(Http1HeaderValidatorTest, RejectUnderscoreHeadersFromRequestHeadersWhenConfigured) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/"},
                                                  {":authority", "envoy.com"},
                                                  {"x_foo", "bar"}};
  auto uhv = createH1(reject_headers_with_underscores_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidUnderscore);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapValid) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{
      {":status", "200"}, {"x-foo", "bar"}, {"transfer-encoding", "chunked"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateResponseHeaderMap(headers));
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapMissingStatus) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapInvalidStatus) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "bar"}, {"x-foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidStatus);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapExtraPseudoHeader) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {":foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(headers),
                             UhvResponseCodeDetail::get().InvalidPseudoHeader);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapEmptyGenericName) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {"", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(headers),
                             UhvResponseCodeDetail::get().EmptyHeaderName);
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapInvaidTransferEncodingStatus100) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "100"},
                                                   {"transfer-encoding", "chunked"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(headers),
                             "uhv.http1.transfer_encoding_not_allowed");
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapInvaidTransferEncodingStatus204) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "204"},
                                                   {"transfer-encoding", "chunked"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(headers),
                             "uhv.http1.transfer_encoding_not_allowed");
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapInvaidTransferEncodingChars) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"},
                                                   {"transfer-encoding", "{chunked}"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateResponseHeaderMap(headers),
                             "uhv.http1.invalid_transfer_encoding");
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseHeaderMapDropUnderscoreHeaders) {
  ::Envoy::Http::TestResponseHeaderMapImpl headers{{":status", "200"}, {"x_foo", "bar"}};
  auto uhv = createH1(drop_headers_with_underscores_config);

  EXPECT_ACCEPT(uhv->validateResponseHeaderMap(headers));
  EXPECT_EQ(headers, ::Envoy::Http::TestResponseHeaderMapImpl({{":status", "200"}}));
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapNormalizePath) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/./dir1/../dir2"},
                                                  {":authority", "envoy.com"}};
  auto uhv = createH1(empty_config);

  EXPECT_TRUE(uhv->validateRequestHeaderMap(headers).ok());
  EXPECT_EQ(headers.path(), "/dir2");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapRejectPath) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{
      {":scheme", "https"}, {":method", "GET"}, {":path", "/.."}, {":authority", "envoy.com"}};
  auto uhv = createH1(empty_config);
  auto result = uhv->validateRequestHeaderMap(headers);
  EXPECT_EQ(result.action(), HeaderValidator::RejectOrRedirectAction::Reject);
  EXPECT_EQ(result.details(), UhvResponseCodeDetail::get().InvalidUrl);
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeaderMapRedirectPath) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/dir1%2fdir2"},
                                                  {":authority", "envoy.com"}};
  auto uhv = createH1(redirect_encoded_slash_config);
  auto result = uhv->validateRequestHeaderMap(headers);
  EXPECT_EQ(result.action(), HeaderValidator::RejectOrRedirectAction::Redirect);
  EXPECT_EQ(result.details(), "uhv.path_noramlization_redirect");
  EXPECT_EQ(headers.path(), "/dir1/dir2");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestHeadersNoPathNormalization) {
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":method", "GET"},
                                                  {":path", "/dir1%2fdir2/.."},
                                                  {":authority", "envoy.com"}};
  auto uhv = createH1(no_path_normalization);
  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
  EXPECT_EQ(headers.path(), "/dir1%2fdir2/..");
}

TEST_F(Http1HeaderValidatorTest, ValidateRequestTrailerMap) {
  auto uhv = createH1(empty_config);
  ::Envoy::Http::TestRequestTrailerMapImpl request_trailer_map{{"trailer1", "value1"},
                                                               {"trailer2", "values"}};
  EXPECT_TRUE(uhv->validateRequestTrailerMap(request_trailer_map));
}

TEST_F(Http1HeaderValidatorTest, ValidateInvalidRequestTrailerMap) {
  auto uhv = createH1(empty_config);
  // H/2 trailers must not contain pseudo headers
  ::Envoy::Http::TestRequestTrailerMapImpl request_trailer_map{{":path", "value1"},
                                                               {"trailer2", "values"}};
  auto result = uhv->validateRequestTrailerMap(request_trailer_map);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.details(), "uhv.invalid_name_characters");
}

TEST_F(Http1HeaderValidatorTest, ValidateInvalidValueRequestTrailerMap) {
  auto uhv = createH1(empty_config);
  ::Envoy::Http::TestRequestTrailerMapImpl request_trailer_map{{"trailer1", "value1"},
                                                               {"trailer2", "values"}};
  ::Envoy::Http::HeaderString invalid_value;
  // \n must not be present in header values
  invalid_value.setCopyUnvalidatedForTestOnly("invalid\nvalue");
  request_trailer_map.addViaMove(::Envoy::Http::HeaderString("trailer3"), std::move(invalid_value));
  auto result = uhv->validateRequestTrailerMap(request_trailer_map);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.details(), "uhv.invalid_value_characters");
}

TEST_F(Http1HeaderValidatorTest, RejectUnderscoreHeadersFromRequestTrailersWhenConfigured) {
  ::Envoy::Http::TestRequestTrailerMapImpl trailers{{"trailer1", "value1"}, {"x_foo", "bar"}};
  auto uhv = createH1(reject_headers_with_underscores_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestTrailerMap(trailers),
                             UhvResponseCodeDetail::get().InvalidUnderscore);
}

TEST_F(Http1HeaderValidatorTest, UnderscoreHeadersAllowedInRequestTrailersByDefault) {
  ::Envoy::Http::TestRequestTrailerMapImpl trailers{{"trailer1", "value1"}, {"x_foo", "bar"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestTrailerMap(trailers));
  EXPECT_EQ(trailers,
            ::Envoy::Http::TestRequestTrailerMapImpl({{"trailer1", "value1"}, {"x_foo", "bar"}}));
}

TEST_F(Http1HeaderValidatorTest, DropUnderscoreHeadersFromRequestTrailers) {
  ::Envoy::Http::TestRequestTrailerMapImpl trailers{{"trailer1", "value1"}, {"x_foo", "bar"}};
  auto uhv = createH1(drop_headers_with_underscores_config);

  EXPECT_ACCEPT(uhv->validateRequestTrailerMap(trailers));
  EXPECT_EQ(trailers, ::Envoy::Http::TestRequestTrailerMapImpl({{"trailer1", "value1"}}));
}

TEST_F(Http1HeaderValidatorTest, ValidateResponseTrailerMap) {
  auto uhv = createH1(empty_config);
  ::Envoy::Http::TestResponseTrailerMapImpl response_trailer_map{{"trailer1", "value1"}};
  EXPECT_TRUE(uhv->validateResponseTrailerMap(response_trailer_map).ok());
}

TEST_F(Http1HeaderValidatorTest, ValidateInvalidResponseTrailerMap) {
  auto uhv = createH1(empty_config);
  // H/2 trailers must not contain pseudo headers
  ::Envoy::Http::TestResponseTrailerMapImpl response_trailer_map{{":status", "200"},
                                                                 {"trailer1", "value1"}};
  auto result = uhv->validateResponseTrailerMap(response_trailer_map);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.details(), "uhv.invalid_name_characters");
}

TEST_F(Http1HeaderValidatorTest, ValidateInvalidValueResponseTrailerMap) {
  auto uhv = createH1(empty_config);
  // The DEL (0x7F) character is illegal in header values
  ::Envoy::Http::TestResponseTrailerMapImpl response_trailer_map{{"trailer0", "abcd\x7F\\ef"},
                                                                 {"trailer1", "value1"}};
  auto result = uhv->validateResponseTrailerMap(response_trailer_map);
  EXPECT_FALSE(result);
  EXPECT_EQ(result.details(), "uhv.invalid_value_characters");
}

TEST_F(Http1HeaderValidatorTest, BackslashInPathIsTranslatedToSlash) {
  scoped_runtime_.mergeValues(
      {{"envoy.reloadable_features.uhv_translate_backslash_to_slash", "true"}});
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":path", "/path\\with/back\\/slash%5c"},
                                                  {":authority", "envoy.com"},
                                                  {":method", "GET"}};
  auto uhv = createH1(empty_config);

  EXPECT_ACCEPT(uhv->validateRequestHeaderMap(headers));
  EXPECT_EQ(headers.path(), "/path/with/back/slash%5C");
}

TEST_F(Http1HeaderValidatorTest, BackslashInPathIsRejectedWithOverride) {
  scoped_runtime_.mergeValues(
      {{"envoy.reloadable_features.uhv_translate_backslash_to_slash", "false"}});
  ::Envoy::Http::TestRequestHeaderMapImpl headers{{":scheme", "https"},
                                                  {":path", "/path\\with/back\\/slash%5c"},
                                                  {":authority", "envoy.com"},
                                                  {":method", "GET"}};
  auto uhv = createH1(empty_config);

  EXPECT_REJECT_WITH_DETAILS(uhv->validateRequestHeaderMap(headers), "uhv.invalid_url");
}

} // namespace
} // namespace EnvoyDefault
} // namespace HeaderValidators
} // namespace Http
} // namespace Extensions
} // namespace Envoy
