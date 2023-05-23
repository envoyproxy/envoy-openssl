#include <openssl/pem.h>
#include <ossl/openssl/pem.h>


int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm, const char *name, BIO *bp, pem_password_cb *cb, void *u) {
  return ossl_PEM_bytes_read_bio(pdata, plen, pnm, name, bp, cb, u);
}
