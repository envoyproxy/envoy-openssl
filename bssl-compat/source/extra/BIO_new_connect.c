#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


// BIO_new_connect returns a BIO that connects to the given hostname and port.
// The |host_and_optional_port| argument should be of the form
// "www.example.com" or "www.example.com:443". If the port is omitted, it must
// be provided with |BIO_set_conn_port|.
//
// It returns the new BIO on success, or NULL on error.
BIO *BIO_new_connect(const char *host_and_optional_port) {
  return ossl_BIO_new_connect(host_and_optional_port);
}
