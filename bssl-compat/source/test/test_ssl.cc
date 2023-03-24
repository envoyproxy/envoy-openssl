#include <gtest/gtest.h>
#include <openssl/base.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <future>


TEST(SSLTest, test_SSL_CTX_set_select_certificate_cb) {
  signal(SIGPIPE, SIG_IGN);

  std::promise<in_port_t> server_port;
  std::vector<uint16_t> extension_types;

  // Start a TLS server with a (SSL_CTX_set_select_certificate_cb()) callback installed.
  std::thread server([&]() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()));
    SSL_CTX_set_ex_data(ctx.get(), 0, &extension_types); // So the callback can fill it in

    // Install the callback.
    SSL_CTX_set_select_certificate_cb(ctx.get(), [](const SSL_CLIENT_HELLO *client_hello) -> enum ssl_select_cert_result_t {
      std::vector<uint16_t> *extension_types = static_cast<std::vector<uint16_t>*>(SSL_CTX_get_ex_data(SSL_get_SSL_CTX(client_hello->ssl), 0));

      CBS extensions;
      CBS_init(&extensions, client_hello->extensions, client_hello->extensions_len);

      while (CBS_len(&extensions)) {
        uint16_t type, length;
        CBS_get_u16(&extensions, &type);
        CBS_get_u16(&extensions, &length);
        CBS_skip(&extensions, length);
        extension_types->push_back(type);
      }

      return ssl_select_cert_success;
    });

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    socklen_t addrlen = sizeof(addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_EQ(0, bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
    ASSERT_EQ(0, listen(sock, 1));
    ASSERT_EQ(0, getsockname(sock, (struct sockaddr*)&addr, &addrlen));
    server_port.set_value(ntohs(addr.sin_port));

    int client = accept(sock, nullptr, nullptr);
    SSL *ssl = SSL_new(ctx.get());
    SSL_set_fd(ssl, client);
    SSL_accept(ssl);
    SSL_write(ssl, "test", 4);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(sock);
  });

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_client_method()));
  bssl::UniquePtr<SSL> ssl (SSL_new(ctx.get()));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  addr.sin_port = htons(server_port.get_future().get());

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_EQ(0, connect(sock, (const struct sockaddr *)&addr, sizeof(addr)));
  SSL_set_fd(ssl.get(), sock);
  SSL_connect(ssl.get());

  std::vector<uint16_t> expected_extension_types {
    ossl_TLSEXT_TYPE_ec_point_formats,
    ossl_TLSEXT_TYPE_supported_groups,
    ossl_TLSEXT_TYPE_session_ticket,
    ossl_TLSEXT_TYPE_encrypt_then_mac,
    ossl_TLSEXT_TYPE_extended_master_secret,
    ossl_TLSEXT_TYPE_signature_algorithms,
    ossl_TLSEXT_TYPE_supported_versions,
    ossl_TLSEXT_TYPE_psk_kex_modes,
    ossl_TLSEXT_TYPE_key_share
  };

  ASSERT_EQ(expected_extension_types, extension_types);

  server.join();
}
