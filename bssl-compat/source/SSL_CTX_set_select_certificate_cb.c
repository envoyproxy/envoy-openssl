#include <openssl/ssl.h>
#include <ossl.h>


static int ssl_ctx_client_hello_cb(SSL *ssl, int *alert, void *arg) {
  enum ssl_select_cert_result_t (*callback)(const SSL_CLIENT_HELLO *) = arg;

  SSL_CLIENT_HELLO client_hello;
  memset(&client_hello, 0, sizeof(client_hello));

  client_hello.ssl = ssl;
  client_hello.version = ossl.ossl_SSL_client_hello_get0_legacy_version(ssl);
  client_hello.random_len = ossl.ossl_SSL_client_hello_get0_random(ssl, &client_hello.random);
  client_hello.session_id_len = ossl.ossl_SSL_client_hello_get0_session_id(ssl, &client_hello.session_id);
  client_hello.cipher_suites_len = ossl.ossl_SSL_client_hello_get0_ciphers(ssl, &client_hello.cipher_suites);
  client_hello.compression_methods_len = ossl.ossl_SSL_client_hello_get0_compression_methods(ssl, &client_hello.compression_methods);

  int *extension_ids;
  size_t extension_ids_len;

  if (!ossl.ossl_SSL_client_hello_get1_extensions_present(ssl, &extension_ids, &extension_ids_len)) {
    *alert = SSL_AD_INTERNAL_ERROR;
    return ossl_SSL_CLIENT_HELLO_ERROR;
  }

  CBB extensions;
  CBB_init(&extensions, 1024);

  for (size_t i = 0; i < extension_ids_len; i++) {
    const unsigned char *extension_data;
    size_t extension_len;

    if (!ossl.ossl_SSL_client_hello_get0_ext(ssl, extension_ids[i], &extension_data, &extension_len) ||
        !CBB_add_u16(&extensions, extension_ids[i]) ||
        !CBB_add_u16(&extensions, extension_len) ||
        !CBB_add_bytes(&extensions, extension_data, extension_len)) {
      OPENSSL_free(extension_ids);
      CBB_cleanup(&extensions);
      *alert = SSL_AD_INTERNAL_ERROR;
      return ossl_SSL_CLIENT_HELLO_ERROR;
    }
  }

  OPENSSL_free(extension_ids);

  if (!CBB_finish(&extensions, (uint8_t**)&client_hello.extensions, &client_hello.extensions_len)) {
    CBB_cleanup(&extensions);
    *alert = SSL_AD_INTERNAL_ERROR;
    return ossl_SSL_CLIENT_HELLO_ERROR;
  }

  enum ssl_select_cert_result_t result = callback(&client_hello);

  OPENSSL_free((void*)client_hello.extensions);

  switch (result) {
    case ssl_select_cert_success: return ossl_SSL_CLIENT_HELLO_SUCCESS;
    case ssl_select_cert_retry:   return ossl_SSL_CLIENT_HELLO_RETRY;
    case ssl_select_cert_error:   return ossl_SSL_CLIENT_HELLO_ERROR;
  };
}

void SSL_CTX_set_select_certificate_cb(SSL_CTX *ctx, enum ssl_select_cert_result_t (*cb)(const SSL_CLIENT_HELLO *)) {
  ossl.ossl_SSL_CTX_set_client_hello_cb(ctx, ssl_ctx_client_hello_cb, cb);
}
