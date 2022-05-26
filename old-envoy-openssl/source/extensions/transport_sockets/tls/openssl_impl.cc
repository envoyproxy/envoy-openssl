#include "extensions/transport_sockets/tls/openssl_impl.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "openssl/crypto.h"
#include "openssl/hmac.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

int alpnSelectCallback(std::vector<uint8_t> parsed_alpn_protocols, const unsigned char** out,
                       unsigned char* outlen, const unsigned char* in, unsigned int inlen) {
  // Currently this uses the standard selection algorithm in priority order.
  const uint8_t* alpn_data = &parsed_alpn_protocols[0];
  size_t alpn_data_size = parsed_alpn_protocols.size();

  if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen, alpn_data, alpn_data_size, in,
                            inlen) != OPENSSL_NPN_NEGOTIATED) {
    return SSL_TLSEXT_ERR_NOACK;
  } else {
    return SSL_TLSEXT_ERR_OK;
  }
}

auto select_client_cert_cb = +[](SSL*, X509**, EVP_PKEY**) -> int {
  std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!! select_client_cert_cb \n";
  return 0;
};

void set_select_certificate_cb(SSL_CTX* ctx) {
  SSL_CTX_set_client_cert_cb(ctx, select_client_cert_cb);
}

bssl::UniquePtr<SSL> newSsl(SSL_CTX* ctx) { return bssl::UniquePtr<SSL>(SSL_new(ctx)); }

int set_strict_cipher_list(SSL_CTX* ctx, const char* str) {
  SSL_CTX_set_cipher_list(ctx, str);

  STACK_OF(SSL_CIPHER)* ciphers = SSL_CTX_get_ciphers(ctx);
  char* dup = strdup(str);
  char* token = std::strtok(dup, ":+![|]");
  while (token != NULL) {
    std::string str1(token);
    bool found = false;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
      const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
      std::string str2(SSL_CIPHER_get_name(cipher));
      if (str1.compare(str2) == 0) {
        found = true;
      }
    }
    if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
      delete dup;
      return 0;
    }

    token = std::strtok(NULL, ":[]|");
  }

  delete dup;
  return 1;
}

std::string getSerialNumberFromCertificate(X509* cert) {
  ASN1_INTEGER* serial_number = X509_get_serialNumber(cert);
  BIGNUM* num_bn(BN_new());
  ASN1_INTEGER_to_BN(serial_number, num_bn);
  char* char_serial_number = BN_bn2hex(num_bn);
  BN_free(num_bn);
  if (char_serial_number != nullptr) {
    std::string serial_number(char_serial_number);

    // openssl is uppercase, boringssl is lowercase. So convert
    std::transform(serial_number.begin(), serial_number.end(), serial_number.begin(), ::tolower);

    OPENSSL_free(char_serial_number);
    return serial_number;
  }
  return "";
}

void allowRenegotiation(SSL*) {
  // SSL_set_renegotiate_mode(ssl, mode);
}

bssl::UniquePtr<STACK_OF(X509_NAME)> initX509Names() {
  bssl::UniquePtr<STACK_OF(X509_NAME)> list(
      sk_X509_NAME_new([](const X509_NAME* const* a, const X509_NAME* const* b) -> int {
        return X509_NAME_cmp(*a, *b);
      }));

  return list;
}

EVP_MD_CTX* newEVP_MD_CTX() {
  EVP_MD_CTX* md(EVP_MD_CTX_new());
  return md;
}

SSL_SESSION* ssl_session_from_bytes(SSL* client_ssl_socket, const SSL_CTX*,
                                    const std::string& client_session) {
  SSL_SESSION* client_ssl_session = SSL_get_session(client_ssl_socket);
  SSL_SESSION_set_app_data(client_ssl_session, client_session.data());
  return client_ssl_session;
}

int ssl_session_to_bytes(const SSL_SESSION*, uint8_t** out_data, size_t* out_len) {
  //   void *data = SSL_SESSION_get_app_data(in);
  //   *out_data = data;
  *out_data = static_cast<uint8_t*>(OPENSSL_malloc(1));
  *out_len = 1;

  return 1;
}

X509* getVerifyCallbackCert(X509_STORE_CTX* store_ctx, void*) {

  X509* x509 = X509_STORE_CTX_get_current_cert(store_ctx);

  if (x509 == nullptr) {
    x509 = X509_STORE_CTX_get0_cert(store_ctx);
  }

  return x509;
}

int ssl_session_is_resumable(const SSL_SESSION*) { return 1; }

void ssl_ctx_add_client_CA(SSL_CTX* ctx, X509* x) { SSL_CTX_add_client_CA(ctx, x); }

int should_be_single_use(const SSL_SESSION*) { return 1; }

// void ssl_ctx_set_client_CA_list(SSL_CTX *ctx, bssl::UniquePtr<STACK_OF(X509_NAME)> list) {
//	if (sk_X509_NAME_num(list.get()) > 0)
//	  SSL_CTX_set_client_CA_list(ctx, list.release());
//}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
