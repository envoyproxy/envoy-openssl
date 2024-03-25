#ifndef _BIO_METH_MAP_H_
#define _BIO_METH_MAP_H_

#include <openssl/bio.h>
#include <ossl/openssl/bio.h>


/**
 * Registers the mapping between the specified BoringSSL BIO_METHOD*, and the OpenSSL ossl_BIO_METHOD*
 */
bool bio_meth_map_register(const BIO_METHOD *bsslMethod, const ossl_BIO_METHOD *osslMethod);

/*
 * Takes a BoringSSL `BIO_METHOD*` and returns the equivalent OpenSSL `ossl_BIO_METHOD*`
 */
const ossl_BIO_METHOD *bio_meth_map_lookup(const BIO_METHOD *bsslMethod);

#endif // _BIO_METH_MAP_H_