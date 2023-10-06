#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

int BIO_meth_set_read(BIO_METHOD *biom,
                      int (*read) (BIO *, char *, int)) {
    return ossl_BIO_meth_set_read(reinterpret_cast<ossl_BIO_METHOD *>(biom), read);
}

}