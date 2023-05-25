#include <openssl/bio.h>
#include "ossl/openssl/bio.h"
#include "log.h"

#include <stdexcept>
#include <cassert>
#include <mutex>
#include <map>


/**
 * Holds the mapping between BoringSSL & OpenSSL BIO_METHOD instances
 */
static std::map<const BIO_METHOD*,const ossl_BIO_METHOD*> map;

/**
 * Protects access to the map above
 */
static std::mutex mutex;

/**
 * Creates a new OpenSSL BIO_METHOD (ossl_BIO_METHOD) equivalent to the
 * specified BoringSSL BIO_METHOD (BIO_METHOD).
 *
 * Since a BoringSSL BIO* is mapped directly to the OpenSSL ossl_BIO* type,
 * we can directly use the read/write/create/destroy/etc function pointers,
 * without having to map them.
 */
static ossl_BIO_METHOD *ossl_BIO_meth_new(const BIO_METHOD *bsslMethod) {
  ossl_BIO_METHOD *osslMethod = ossl_BIO_meth_new(bsslMethod->type, bsslMethod->name);

  // BSSL: int (*bwrite)(BIO *, const char *, int);
  // OSSL: int BIO_meth_set_write(BIO_METHOD *biom, int (*write)(BIO *, const char *, int));
  ossl_BIO_meth_set_write(osslMethod, bsslMethod->bwrite);

  // BSSL: int (*bread)(BIO *, char *, int);
  // OSSL: int BIO_meth_set_read(BIO_METHOD *biom, int (*read)(BIO *, char *, int));
  ossl_BIO_meth_set_read(osslMethod, bsslMethod->bread);

  // BSSL: int (*bputs)(BIO *, const char *);
  // OSSL: int ossl_BIO_meth_set_puts(ossl_BIO_METHOD *biom, int (*puts)(ossl_BIO *, const char *))
  ossl_BIO_meth_set_puts(osslMethod, bsslMethod->bputs);

  // BSSL: int (*bgets)(BIO *, char *, int);
  // OSSL: int ossl_BIO_meth_set_gets(ossl_BIO_METHOD *biom, int (*gets)(ossl_BIO *, char *, int))
  ossl_BIO_meth_set_gets(osslMethod, bsslMethod->bgets);

  // BSSL: long (*ctrl)(BIO *, int, long, void *);
  // OSSL: int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl)(BIO *, int, long, void *));
  ossl_BIO_meth_set_ctrl(osslMethod, bsslMethod->ctrl);

  // BSSL: int (*create)(BIO *);
  // OSSL: int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *));
  ossl_BIO_meth_set_create(osslMethod, bsslMethod->create);

  // BSSL: int (*destroy)(BIO *);
  // OSSL: int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *));
  ossl_BIO_meth_set_destroy(osslMethod, bsslMethod->destroy);

  // BSSL: long (*callback_ctrl)(BIO *, int, bio_info_cb);
  // OSSL: int ossl_BIO_meth_set_callback_ctrl(ossl_BIO_METHOD *biom, long (*callback_ctrl)(ossl_BIO *, int, ossl_BIO_info_cb *))
  if (bsslMethod->callback_ctrl == nullptr) {
    ossl_BIO_meth_set_callback_ctrl(osslMethod, nullptr);
  }
  else {
    bssl_compat_fatal("BIO_METHOD::callback_ctrl is not supported");
  }

  return osslMethod;
}

/**
 * Registers the mapping between the specified BoringSSL BIO_METHOD*, and the OpenSSL ossl_BIO_METHOD*
 */
static bool BIO_meth_register(const BIO_METHOD *bsslMethod, const ossl_BIO_METHOD*osslMethod) {
  std::lock_guard<std::mutex> lock(mutex);
  auto i = map.insert(std::make_pair(bsslMethod, osslMethod));
  return i.second;
}

/*
 * Takes a BoringSSL BIO_METHOD and returns the equivalent OpenSSL BIO_METHOD
 */
static const ossl_BIO_METHOD *b2o(const BIO_METHOD *bsslMethod) {
  std::lock_guard<std::mutex> lock(mutex);
  auto i = map.find(bsslMethod);

  if (i == map.end()) {
    ossl_BIO_METHOD *osslMethod = ossl_BIO_meth_new(bsslMethod);
    map.insert(std::make_pair(bsslMethod, osslMethod));
    return osslMethod;
  }
  else {
    return i->second;
  }
}

/*
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L191
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L223
 */
void BIO_clear_retry_flags(BIO *bio) {
  ossl_BIO_clear_retry_flags(bio);
}

/*
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_free.html
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L86-L92
 */
int BIO_free(BIO *bio) {
  // In BoringSSL, the BIO_free() call frees the whole chain,
  // whereas in OpenSSL, it just frees the single bio.
  ossl_BIO_free_all(bio);
  return 1;
}

/*
 * OSSL: Doesn't exist
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L391
 */
int BIO_mem_contents(const BIO *bio, const uint8_t **out_contents, size_t *out_len) {
  auto len = ossl_BIO_get_mem_data(const_cast<BIO*>(bio), out_contents);

  if (len == 0) { // A 0 return means either error or empty
    if (ossl_BIO_ctrl_pending(const_cast<BIO*>(bio)) != 0) {
      return 0; // Not empty so must be error
    }
  }

  *out_len = len;
  return 1;
}

/*
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L721
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_new_bio_pair.html
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L616
 */
int BIO_new_bio_pair(BIO **out1, size_t writebuf1, BIO **out2, size_t writebuf2) {
  int rc = ossl_BIO_new_bio_pair(out1, writebuf1, out2, writebuf2);
  if (rc == 0) {
    *out1 = nullptr;
    *out2 = nullptr;
  }
  return rc;
}

/*
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L549
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_new.html
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L82
 *
 * The OpenSSL docs say nothing about the reference count of the new BIO, whereas the BoringSSL
 * docs say that it will have a reference count of one. Checking the OpenSSL source shows that
 * it does also initialise the reference count to 1.
 */
BIO *BIO_new(const BIO_METHOD *bsslMethod) {
  return ossl_BIO_new(b2o(bsslMethod));
}

/*
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_new_mem_buf.html
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L591
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L386
 */
BIO *BIO_new_mem_buf(const void *buf, int len) {
  return ossl_BIO_new_mem_buf(buf, len);
}

/*
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_puts.html
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L564
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L130
 */
int BIO_puts(BIO *bio, const char *buf) {
  return ossl_BIO_puts(bio, buf);
}

/*
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_set_mem_eof_return.html
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L422
 */
int BIO_set_mem_eof_return(BIO *bio, int eof_value) {
  return ossl_BIO_set_mem_eof_return(bio, eof_value);
}

/*
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L185
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L211
 */
void BIO_set_retry_read(BIO *bio) {
  ossl_BIO_set_retry_read(bio);
}

/*
 * OSSL: https://github.com/openssl/openssl/blob/ac3cef223a4c61d6bee34527b6d4c8c6432494a7/include/openssl/bio.h#L187
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L215
 */
void BIO_set_retry_write(BIO *bio) {
  ossl_BIO_set_retry_write(bio);
}

static const BIO_METHOD *BIO_s_mem_create(void) {
  const ossl_BIO_METHOD *osslMethod = ossl_BIO_s_mem();
  static const BIO_METHOD bsslMethod = {
      BIO_TYPE_MEM,
      "memory buffer",
      ossl_BIO_meth_get_write(osslMethod),
      ossl_BIO_meth_get_read(osslMethod),
      ossl_BIO_meth_get_puts(osslMethod),
      ossl_BIO_meth_get_gets(osslMethod),
      ossl_BIO_meth_get_ctrl(osslMethod),
      ossl_BIO_meth_get_create(osslMethod),
      ossl_BIO_meth_get_destroy(osslMethod),
      nullptr /* callback_ctrl */,
  };
  static bool registered = BIO_meth_register(&bsslMethod, osslMethod);
  (void)registered;

  return &bsslMethod;
}

const BIO_METHOD *BIO_s_mem() {
   static const BIO_METHOD *result = BIO_s_mem_create();
   return result;
}

static const BIO_METHOD *BIO_s_socket_create(void) {
  static const ossl_BIO_METHOD *osslMethod = ossl_BIO_s_socket();
  static const BIO_METHOD bsslMethod = {
      BIO_TYPE_SOCKET,
      "socket",
      ossl_BIO_meth_get_write(osslMethod),
      ossl_BIO_meth_get_read(osslMethod),
      ossl_BIO_meth_get_puts(osslMethod),
      ossl_BIO_meth_get_gets(osslMethod),
      ossl_BIO_meth_get_ctrl(osslMethod),
      ossl_BIO_meth_get_create(osslMethod),
      ossl_BIO_meth_get_destroy(osslMethod),
      nullptr /* callback_ctrl */,
  };
  static bool registered = BIO_meth_register(&bsslMethod, osslMethod);
  (void)registered;

  return &bsslMethod;
}

const BIO_METHOD *BIO_s_socket() {
   static const BIO_METHOD *result = BIO_s_socket_create();
   return result;
}

/*
 * OSSL: https://www.openssl.org/docs/man1.1.1/man3/BIO_vfree.html
 * BSSL: https://github.com/google/boringssl/blob/cacb5526268191ab52e3a8b2d71f686115776646/src/include/openssl/bio.h#L98
 */
void BIO_vfree(BIO *bio) {
  BIO_free(bio);
}

