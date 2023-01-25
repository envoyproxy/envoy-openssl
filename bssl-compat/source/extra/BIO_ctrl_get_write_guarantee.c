#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_ctrl_get_write_guarantee returns the number of bytes that |bio| (which
// must have been returned by |BIO_new_bio_pair|) will accept on the next
// |BIO_write| call.
size_t BIO_ctrl_get_write_guarantee(BIO *bio) {
  return ossl_BIO_ctrl_get_write_guarantee(bio);
}
