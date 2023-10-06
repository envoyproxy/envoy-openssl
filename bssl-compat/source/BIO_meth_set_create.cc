#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

int BIO_meth_set_create(BIO_METHOD *method,
                        int (*create)(BIO *)) {
    return ossl_BIO_meth_set_create(reinterpret_cast<ossl_BIO_METHOD *>(method), create);
}

}