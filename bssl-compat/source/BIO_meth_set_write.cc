#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

int BIO_meth_set_write(BIO_METHOD *method,
                       int (*write)(BIO *, const char *, int)) {
    return ossl_BIO_meth_set_write(reinterpret_cast<ossl_BIO_METHOD *>(method), write);
}

}