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
  std::set<uint16_t> received_ext_types;

  // Start a TLS server with a (SSL_CTX_set_select_certificate_cb()) callback installed.
  std::thread server([&]() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()));
    SSL_CTX_set_ex_data(ctx.get(), 0, &received_ext_types); // So the callback can fill it in

    // Install the callback.
    SSL_CTX_set_select_certificate_cb(ctx.get(), [](const SSL_CLIENT_HELLO *client_hello) -> enum ssl_select_cert_result_t {
      std::set<uint16_t> *received_ext_types = static_cast<std::set<uint16_t>*>(SSL_CTX_get_ex_data(SSL_get_SSL_CTX(client_hello->ssl), 0));

      CBS extensions;
      CBS_init(&extensions, client_hello->extensions, client_hello->extensions_len);

      while (CBS_len(&extensions)) {
        uint16_t type, length;
        CBS_get_u16(&extensions, &type);
        CBS_get_u16(&extensions, &length);
        CBS_skip(&extensions, length);
        received_ext_types->insert(type);
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

  // OpenSSL and BoringSSL clients send a slightly different set of client hello
  // extensions by default, but this is the common set that we should expect.
  std::set<uint16_t> expected_ext_types {
    TLSEXT_TYPE_extended_master_secret,
    TLSEXT_TYPE_supported_groups,
    TLSEXT_TYPE_ec_point_formats,
    TLSEXT_TYPE_session_ticket,
    TLSEXT_TYPE_signature_algorithms,
    TLSEXT_TYPE_key_share,
    TLSEXT_TYPE_psk_key_exchange_modes,
    TLSEXT_TYPE_supported_versions
  };

  ASSERT_TRUE (std::includes(received_ext_types.begin(), received_ext_types.end(),
                             expected_ext_types.begin(), expected_ext_types.end()));

  server.join();
}


static const char *version_str(uint16_t version) {
    switch (version) {
      case SSL3_VERSION :   { return "SSL3_VERSION  "; break; }
      case TLS1_VERSION :   { return "TLS1_VERSION  "; break; }
      case TLS1_1_VERSION : { return "TLS1_1_VERSION"; break; }
      case TLS1_2_VERSION : { return "TLS1_2_VERSION"; break; }
      case TLS1_3_VERSION : { return "TLS1_3_VERSION"; break; }
      default:              { return "<UNKNOWN>     "; break; }
    };
}

TEST(SSLTest,SSL_CIPHER_get_min_version) {
  std::map<std::string,uint16_t> boring_cipher_versions {
    {"ECDHE-ECDSA-AES128-GCM-SHA256", TLS1_2_VERSION},
    {"ECDHE-RSA-AES128-GCM-SHA256", TLS1_2_VERSION},
    {"ECDHE-ECDSA-AES256-GCM-SHA384", TLS1_2_VERSION},
    {"ECDHE-RSA-AES256-GCM-SHA384", TLS1_2_VERSION},
    {"ECDHE-ECDSA-CHACHA20-POLY1305", TLS1_2_VERSION},
    {"ECDHE-RSA-CHACHA20-POLY1305", TLS1_2_VERSION},
    {"ECDHE-PSK-CHACHA20-POLY1305", TLS1_2_VERSION},
    {"ECDHE-ECDSA-AES128-SHA", SSL3_VERSION  },
    {"ECDHE-RSA-AES128-SHA", SSL3_VERSION  },
    {"ECDHE-PSK-AES128-CBC-SHA", SSL3_VERSION  },
    {"ECDHE-ECDSA-AES256-SHA", SSL3_VERSION  },
    {"ECDHE-RSA-AES256-SHA", SSL3_VERSION  },
    {"ECDHE-PSK-AES256-CBC-SHA", SSL3_VERSION  },
    {"AES128-GCM-SHA256", TLS1_2_VERSION},
    {"AES256-GCM-SHA384", TLS1_2_VERSION},
    {"AES128-SHA", SSL3_VERSION  },
    {"PSK-AES128-CBC-SHA", SSL3_VERSION  },
    {"AES256-SHA", SSL3_VERSION  },
    {"PSK-AES256-CBC-SHA", SSL3_VERSION  },
    {"DES-CBC3-SHA", SSL3_VERSION  },
  };

  bssl::UniquePtr<SSL_CTX> ctx {SSL_CTX_new(TLS_server_method())};
  bssl::UniquePtr<SSL> ssl {SSL_new(ctx.get())};

  STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl.get());
  for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
    const SSL_CIPHER *cipher {sk_SSL_CIPHER_value(ciphers, i)};
    const char *name {SSL_CIPHER_get_name(cipher)};
    uint16_t min_version {SSL_CIPHER_get_min_version(cipher)};

    if (boring_cipher_versions.find(name) != boring_cipher_versions.end()) {
      EXPECT_STREQ(version_str(boring_cipher_versions[name]), version_str(min_version)) << " for " << name;
    }
  }
}

TEST(SSLTest, SSL_error_description) {
  EXPECT_STREQ("WANT_ACCEPT", SSL_error_description(SSL_ERROR_WANT_ACCEPT));
  EXPECT_EQ(nullptr, SSL_error_description(123456));
}