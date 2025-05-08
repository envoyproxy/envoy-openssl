#include <openssl/ssl.h>
#include <ossl.h>


static const char *kCiphers[] = {
    // The RSA ciphers

    // Cipher 0A
 
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
 

    // New AES ciphersuites

    // Cipher 2F
 
        "TLS_RSA_WITH_AES_128_CBC_SHA",
 
    // Cipher 35
 
        "TLS_RSA_WITH_AES_256_CBC_SHA",
 

    // PSK cipher suites.

    // Cipher 8C

        "TLS_PSK_WITH_AES_128_CBC_SHA",

    // Cipher 8D

        "TLS_PSK_WITH_AES_256_CBC_SHA",

    // GCM ciphersuites from RFC 5288

    // Cipher 9C
 
        "TLS_RSA_WITH_AES_128_GCM_SHA256",


    // Cipher 9D

        "TLS_RSA_WITH_AES_256_GCM_SHA384",

    // TLS 1.3 suites.

    // Cipher 1301

        "TLS_AES_128_GCM_SHA256",

    // Cipher 1302

        "TLS_AES_256_GCM_SHA384",
 
    // Cipher 1303

        "TLS_CHACHA20_POLY1305_SHA256",


    // Cipher C009

        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",


    // Cipher C00A

        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",


    // Cipher C013
 
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
 

    // Cipher C014

        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",


    // Cipher C027

        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",

    // GCM based TLS v1.2 ciphersuites from RFC 5289

    // Cipher C02B
 
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",

    // Cipher C02C

        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
 
    // Cipher C02F
 
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",


    // Cipher C030

        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",

    // ECDHE-PSK cipher suites.

    // Cipher C035
 
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",


    // Cipher C036

        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",


    // ChaCha20-Poly1305 cipher suites.

    // Cipher CCA8

        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",

    // Cipher CCA9

        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

    // Cipher CCAB

        "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",

};

static const char *kUnknownCipher = "(NONE)";

size_t SSL_get_all_cipher_names(const char **out, size_t max_out) {

  size_t cipherSize = (sizeof(kCiphers) / sizeof(kCiphers[0]));
   if(max_out != 0) {
     *out++ = kUnknownCipher;
     for(int i = 0; i < cipherSize; i++) {
        *out++ = kCiphers[i];
     }
   }
   return 1+cipherSize;
}

