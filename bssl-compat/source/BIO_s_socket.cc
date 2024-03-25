#include <openssl/bio.h>
#include <ossl.h>
#include "bio_meth_map.h"


static const BIO_METHOD *BIO_s_socket_create(void) {
  static const ossl_BIO_METHOD *osslMethod = ossl.ossl_BIO_s_socket();
  static const BIO_METHOD bsslMethod = {
      BIO_TYPE_SOCKET,
      "socket",
      ossl.ossl_BIO_meth_get_write(osslMethod),
      ossl.ossl_BIO_meth_get_read(osslMethod),
      ossl.ossl_BIO_meth_get_puts(osslMethod),
      ossl.ossl_BIO_meth_get_gets(osslMethod),
      ossl.ossl_BIO_meth_get_ctrl(osslMethod),
      ossl.ossl_BIO_meth_get_create(osslMethod),
      ossl.ossl_BIO_meth_get_destroy(osslMethod),
      nullptr /* callback_ctrl */,
  };
  static bool registered = bio_meth_map_register(&bsslMethod, osslMethod);
  (void)registered;

  return &bsslMethod;
}

extern "C" const BIO_METHOD *BIO_s_socket() {
   static const BIO_METHOD *result = BIO_s_socket_create();
   return result;
}
