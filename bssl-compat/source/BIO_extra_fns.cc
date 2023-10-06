// OpenSSL Functions not implemented in BoringSSL

#include <openssl/bio.h>
#include <ossl.h>

extern "C" {

/**
 * https://www.openssl.org/docs/man3.0/man3/BIO_set_app_data.html
 *
 * @param bio
 * @param data
 */
void BIO_set_app_data(BIO *bio, void *data) {
    ossl_BIO_set_app_data(bio, data);
}

/**
 * https://www.openssl.org/docs/man3.0/man3/BIO_get_app_data.html
 *
 * @param bio
 * @return
 */
void *BIO_get_app_data(BIO *bio) {
    return ossl_BIO_get_app_data(bio);
}

}