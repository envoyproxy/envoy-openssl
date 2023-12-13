#include "source/common/filesystem/filesystem_impl.h"
#include "source/exe/main_common.h"
#include "source/server/admin/admin_html_util.h"

#include "absl/strings/match.h"

namespace Envoy {
namespace {

/**
 * Handles Admin requests to /test?file=$file, reading XXX from
 * test/integration/admin_server/$file, returning "Bad Request" if
 * query param "file" is not present, and "Not Found" if there was
 * a query param but it could not be found.
 *
 * This test-server is only for testing; it potentially makes the
 * entire file-system avail
 */
Http::Code testCallback(Http::ResponseHeaderMap& response_headers, Buffer::Instance& response,
                        Server::AdminStream& admin_stream) {
  Http::Utility::QueryParams query_params = admin_stream.queryParams();
  auto iter = query_params.find("file");
  if (iter == query_params.end()) {
    response.add("query param 'file' missing");
    return Http::Code::BadRequest;
  }
  absl::string_view leaf = iter->second;

  // ".." is not a good thing to allow into the path, even for a test server.
  if (leaf.find("..") != absl::string_view::npos) {
    response.add("bad file argument");
    return Http::Code::BadRequest;
  }

  Filesystem::InstanceImpl file_system;
  std::string path = absl::StrCat("test/integration/admin_html/", iter->second);
  TRY_ASSERT_MAIN_THREAD { response.add(file_system.fileReadToEnd(path)); }
  END_TRY
  catch (EnvoyException& e) {
    response.add(e.what());
    return Http::Code::NotFound;
  }
  if (absl::EndsWith(path, ".html")) {
    response_headers.setReferenceContentType(Http::Headers::get().ContentTypeValues.Html);
  } else if (absl::EndsWith(path, ".js")) {
    response_headers.setReferenceContentType("text/javascript");
  }
  return Http::Code::OK;
}

class DebugHtmlResourceProvider : public Server::AdminHtmlUtil::ResourceProvider {
public:
  absl::string_view getResource(absl::string_view resource_name, std::string& buf) override {
    std::string path = absl::StrCat("source/server/admin/html/", resource_name);
    Filesystem::InstanceImpl file_system;
    TRY_ASSERT_MAIN_THREAD {
      buf = file_system.fileReadToEnd(path);
      ENVOY_LOG_MISC(info, "Read {} bytes from {}", buf.size(), path);
    }
    END_TRY
    catch (EnvoyException& e) {
      ENVOY_LOG_MISC(error, "Error reading file {}", e.what());
      buf = e.what();
    }
    return buf;
  }
};

} // namespace
} // namespace Envoy

/**
 * Envoy server with an additional '/test' admin endpoint for serving test
 * files.
 */
int main(int argc, char** argv) {
  // The CSS, JS, and HTML resources needed for the admin panel are captured at
  // build time as C++ string_view constants, so that the Envoy binary is
  // self-contained. However, this makes iteration on those resources require a
  // C++ recompile and server restart. During debug, you can run with "debug"
  // as the first argument, and we can inject a resource provider that reads
  // those files from the file-system on ever access. This makes iteration on
  // the web interface rapid and fun.
  if (argc > 1 && absl::string_view("debug") == argv[1]) {
    Envoy::Server::AdminHtmlUtil::setResourceProvider(
        std::make_unique<Envoy::DebugHtmlResourceProvider>());
    argv[1] = argv[0];
    --argc;
    ++argv;
  }

  // Install the "/test" endpoint in the admin console, which enables serving
  // the Javascript test framework and fixture to be served with same
  // origin. That is essential to the test's operation, as it depends on
  // a friendly iframe, which most be served on the same host and port.
  return Envoy::MainCommon::main(argc, argv, [](Envoy::Server::Instance& server) {
    Envoy::OptRef<Envoy::Server::Admin> admin = server.admin();
    if (admin.has_value()) {
      admin->addHandler("/test", "test file-serving endpoint", Envoy::testCallback, false, false);
    }
  });
}
