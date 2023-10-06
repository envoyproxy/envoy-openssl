#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

void BIO_meth_free(BIO_METHOD *method) {
    ossl_BIO_meth_free(reinterpret_cast<ossl_BIO_METHOD *>(method));
}

}