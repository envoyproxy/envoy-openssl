#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

BIO_METHOD *BIO_meth_new(int type, const char *name) {
    return reinterpret_cast<BIO_METHOD *>(ossl_BIO_meth_new(type, name));
}

}