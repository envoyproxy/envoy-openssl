#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

int BIO_meth_set_ctrl(BIO_METHOD *method,
                      long (*ctrl)(BIO *, int, long, void *)) {
    return ossl_BIO_meth_set_ctrl(reinterpret_cast<ossl_BIO_METHOD *>(method), ctrl);
}

}