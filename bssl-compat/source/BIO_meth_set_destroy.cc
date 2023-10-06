#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

OPENSSL_EXPORT int BIO_meth_set_destroy(BIO_METHOD *method,
                                        int (*destroy)(BIO *)) {
    return ossl_BIO_meth_set_destroy(reinterpret_cast<ossl_BIO_METHOD *>(method), destroy);
}

}