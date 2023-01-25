#include <openssl/err.h>
#include <ossl/openssl/err.h>


// ERR_get_error gets the packed error code for the least recent error and
// removes that error from the queue. If there are no errors in the queue then
// it returns zero.
uint32_t ERR_get_error(void) {
  return ossl_ERR_get_error();
}
