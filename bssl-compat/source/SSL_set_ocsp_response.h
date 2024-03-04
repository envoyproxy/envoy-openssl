#ifndef _SSL_SET_OCSP_RESPONSE_H_
#define _SSL_SET_OCSP_RESPONSE_H_

#include <openssl/ssl.h>


int ssl_apply_deferred_ocsp_response_cb(SSL *ssl, void *arg);

#endif /*_SSL_SET_OCSP_RESPONSE_H_*/