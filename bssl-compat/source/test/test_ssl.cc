#include <gtest/gtest.h>
#include <openssl/base.h>
#include <openssl/bytestring.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <future>

#include "certs/client_2_cert_chain.pem.h"
#include "certs/client_2_key.pem.h"
#include "certs/server_2_cert_chain.pem.h"
#include "certs/server_2_key.pem.h"
#include "certs/root_ca_cert.pem.h"


class TempFile {
  public:

    TempFile(const char *content) : m_path { "/tmp/XXXXXX" }
    {
      int fd { mkstemp(m_path.data()) };
      if (fd == -1) {
        perror("mkstemp()");
      }
      else {
        for (int n, written = 0, len = strlen(content); written < len; written += n) {
          if ((n = write(fd, content + written, len - written)) < 0) {
            if (errno == EINTR || errno == EAGAIN) {
              continue;
            }
            perror("write()");
          }
        }
        if (close(fd) == -1) {
          perror("close()");
        }
      }
    }

    ~TempFile() {
      if (unlink(m_path.c_str()) == -1) {
        perror("unlink()");
      }
    }

    const char *path() const {
      return m_path.c_str();
    }

  private:

    std::string m_path { "/tmp/XXXXXX" };
};



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

TEST(SSLTest, SSL_enable_ocsp_stapling) {
  bssl::UniquePtr<SSL_CTX> ctx {SSL_CTX_new(TLS_server_method())};
  bssl::UniquePtr<SSL> ssl {SSL_new(ctx.get())};
  SSL_enable_ocsp_stapling(ssl.get());
}

TEST(SSLTest, SSL_set_SSL_CTX) {
  bssl::UniquePtr<SSL_CTX> ctx1 {SSL_CTX_new(TLS_server_method())};
  bssl::UniquePtr<SSL_CTX> ctx2 {SSL_CTX_new(TLS_server_method())};
  bssl::UniquePtr<SSL> ssl {SSL_new(ctx1.get())};

  EXPECT_EQ(ctx1.get(), SSL_get_SSL_CTX(ssl.get()));
  EXPECT_EQ(ctx2.get(), SSL_set_SSL_CTX(ssl.get(), ctx2.get()));
  EXPECT_EQ(ctx2.get(), SSL_get_SSL_CTX(ssl.get()));
  EXPECT_EQ(ctx2.get(), SSL_set_SSL_CTX(ssl.get(), ctx2.get()));
  EXPECT_EQ(ctx2.get(), SSL_get_SSL_CTX(ssl.get()));
}

TEST(SSLTest, SSL_set_renegotiate_mode) {
  bssl::UniquePtr<SSL_CTX> ctx {SSL_CTX_new(TLS_server_method())};
  bssl::UniquePtr<SSL> ssl {SSL_new(ctx.get())};

  SSL_set_renegotiate_mode(ssl.get(), ssl_renegotiate_never);
  SSL_set_renegotiate_mode(ssl.get(), ssl_renegotiate_freely);
}

TEST(SSLTest, SSL_set_ocsp_response) {
  bssl::UniquePtr<SSL_CTX> ctx {SSL_CTX_new(TLS_server_method())};
  bssl::UniquePtr<SSL> ssl {SSL_new(ctx.get())};

  const uint8_t response1[] { 1, 2, 3, 4 };
  const uint8_t response2[] { 1, 2, 3, 4 };

  EXPECT_TRUE(SSL_set_ocsp_response(ssl.get(), nullptr, 0));
  EXPECT_TRUE(SSL_set_ocsp_response(ssl.get(), response1, sizeof(response1)));
  EXPECT_TRUE(SSL_set_ocsp_response(ssl.get(), response2, sizeof(response2)));
  EXPECT_TRUE(SSL_set_ocsp_response(ssl.get(), nullptr, 0));
}

TEST(SSLTest, SSL_SESSION_should_be_single_use) {
  bssl::UniquePtr<SSL_CTX> ctx {SSL_CTX_new(TLS_server_method())};
  bssl::UniquePtr<SSL_SESSION> session {SSL_SESSION_new(ctx.get())};

  ASSERT_TRUE(SSL_SESSION_set_protocol_version(session.get(), TLS1_3_VERSION));
  ASSERT_EQ(1, SSL_SESSION_should_be_single_use(session.get()));
  ASSERT_TRUE(SSL_SESSION_set_protocol_version(session.get(), TLS1_2_VERSION));
  ASSERT_EQ(0, SSL_SESSION_should_be_single_use(session.get()));
}

TEST(SSLTest, test_SSL_get_peer_full_cert_chain) {
  TempFile root_ca_cert_pem        { root_ca_cert_pem_str };
  TempFile client_2_key_pem        { client_2_key_pem_str };
  TempFile client_2_cert_chain_pem { client_2_cert_chain_pem_str };
  TempFile server_2_key_pem        { server_2_key_pem_str };
  TempFile server_2_cert_chain_pem { server_2_cert_chain_pem_str };

  const char MESSAGE[] { "HELLO" };
  std::promise<in_port_t> server_port;

  signal(SIGPIPE, SIG_IGN);

  // Start a TLS server
  std::thread server([&]() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()));

    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    ASSERT_EQ(1, SSL_CTX_load_verify_locations(ctx.get(), root_ca_cert_pem.path(), nullptr)) << (ERR_print_errors_fp(stderr), "");

    STACK_OF(X509_NAME) *cert_names { sk_X509_NAME_new_null() };
    ASSERT_EQ(1, SSL_add_file_cert_subjects_to_stack(cert_names, root_ca_cert_pem.path()));
    SSL_CTX_set_client_CA_list(ctx.get(), cert_names);

    ASSERT_EQ(1, SSL_CTX_use_certificate_chain_file(ctx.get(), server_2_cert_chain_pem.path()));
    ASSERT_EQ(1, SSL_CTX_use_PrivateKey_file(ctx.get(), server_2_key_pem.path(), SSL_FILETYPE_PEM));

    bssl::UniquePtr<SSL> ssl { SSL_new(ctx.get()) };

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    socklen_t addrlen = sizeof(addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_LT(0, sock);
    ASSERT_EQ(0, bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
    ASSERT_EQ(0, listen(sock, 1));
    ASSERT_EQ(0, getsockname(sock, (struct sockaddr*)&addr, &addrlen));
    server_port.set_value(ntohs(addr.sin_port)); // Tell the client our port number
    int client = accept(sock, nullptr, nullptr);
    ASSERT_LT(0, client);

    ASSERT_EQ(1, SSL_set_fd(ssl.get(), client));
    ASSERT_EQ(1, SSL_accept(ssl.get())) << (ERR_print_errors_fp(stderr), "");
    ASSERT_EQ(1, SSL_is_server(ssl.get()));

    STACK_OF(X509) *client_certs { SSL_get_peer_full_cert_chain(ssl.get()) };
    ASSERT_TRUE(client_certs);
    ASSERT_EQ(4, sk_X509_num(client_certs));

#ifdef BSSL_COMPAT
    sk_X509_free(client_certs); // bssl-compat library gives us ownership, but BoringSSL doesn't
#endif

    char buf[sizeof(MESSAGE)];
    ASSERT_EQ(sizeof(MESSAGE), SSL_read(ssl.get(), buf, sizeof(buf)));
    ASSERT_EQ(sizeof(MESSAGE), SSL_write(ssl.get(), MESSAGE, sizeof(MESSAGE)));

    SSL_shutdown(ssl.get());
    close(client);
    close(sock);
  });

  {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_client_method()));

    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    ASSERT_EQ(1, SSL_CTX_load_verify_locations(ctx.get(), root_ca_cert_pem.path(), nullptr));

    ASSERT_EQ(1, SSL_CTX_use_certificate_chain_file(ctx.get(), client_2_cert_chain_pem.path())) << (ERR_print_errors_fp(stderr), "");
    ASSERT_EQ(1, SSL_CTX_use_PrivateKey_file(ctx.get(), client_2_key_pem.path(), SSL_FILETYPE_PEM));

    bssl::UniquePtr<SSL> ssl (SSL_new(ctx.get()));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(server_port.get_future().get());

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_EQ(0, connect(sock, (const struct sockaddr *)&addr, sizeof(addr)));
    ASSERT_EQ(1, SSL_set_fd(ssl.get(), sock));
    ASSERT_TRUE(SSL_connect(ssl.get()) > 0) << (ERR_print_errors_fp(stderr), "");

    STACK_OF(X509) *server_certs = SSL_get_peer_full_cert_chain(ssl.get());
    ASSERT_TRUE(server_certs);
    ASSERT_EQ(4, sk_X509_num(server_certs));

#ifdef BSSL_COMPAT
    sk_X509_free(server_certs); // bssl-compat library gives us ownership, but BoringSSL doesn't
#endif

    char buf[sizeof(MESSAGE)];
    ASSERT_EQ(sizeof(MESSAGE), SSL_write(ssl.get(), MESSAGE, sizeof(MESSAGE)));
    ASSERT_EQ(sizeof(MESSAGE), SSL_read(ssl.get(), buf, sizeof(buf)));
  }

  server.join();
}

TEST(SSLTest, test_SSL_CTX_set_strict_cipher_list) {
  bssl::UniquePtr<SSL_CTX> ctx {SSL_CTX_new(TLS_server_method())};
  STACK_OF(SSL_CIPHER) *ciphers {SSL_CTX_get_ciphers(ctx.get())};

  std::string cipherstr;

  for(const SSL_CIPHER *cipher : ciphers) {
    cipherstr += (cipherstr.size() ? ":" : "");
    cipherstr += SSL_CIPHER_get_name(cipher);
  }

  ASSERT_EQ(1, SSL_CTX_set_strict_cipher_list(ctx.get(), cipherstr.c_str()));
  ASSERT_EQ(0, SSL_CTX_set_strict_cipher_list(ctx.get(), "rubbish:garbage"));
}

TEST(SSLTest, test_SSL_CTX_set_verify_algorithm_prefs) {
  bssl::UniquePtr<SSL_CTX> ctx {SSL_CTX_new(TLS_server_method())};

  uint16_t prefs[] {
    SSL_SIGN_RSA_PSS_RSAE_SHA256,
    SSL_SIGN_ECDSA_SECP256R1_SHA256
  };

  ASSERT_EQ(1, SSL_CTX_set_verify_algorithm_prefs(ctx.get(), prefs, (sizeof(prefs) / sizeof(prefs[0]))));
}