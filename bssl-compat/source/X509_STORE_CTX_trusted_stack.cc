#include <openssl/x509.h>
#include <ossl.h>


/*
 * https://github.com/google/boringssl/blob/557b80f1a3e599459367391540488c132a000d55/include/openssl/x509.h#L2843
 * https://www.openssl.org/docs/man3.0/man3/X509_STORE_CTX_trusted_stack.html
 */
extern "C" void X509_STORE_CTX_trusted_stack(X509_STORE_CTX *ctx, STACK_OF(X509) *sk) {
  ossl.ossl_X509_STORE_CTX_trusted_stack(ctx, reinterpret_cast<ossl_STACK_OF(ossl_X509)*>(sk));
}
