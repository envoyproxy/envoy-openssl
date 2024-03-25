#include <openssl/bio.h>
#include "ossl.h"
#include "log.h"

#include <stdexcept>
#include <cassert>
#include <mutex>
#include <map>


/*
 * The `BIO_METHOD` type is used to represent a ”type” of `BIO` e.g. socket,
 * file, memory etc. A number of builtin `BIO_METHOD` instances are provided by
 * default, and the user can also create their own custom instances.
 *
 * In BoringSSL, the `BIO_METHOD` type is defined as a struct containing a
 * `type`, a `name`, and a number of function pointers for `bread()`,
 * `bwrite()`, `gets()`, `puts()` etc. Instances of this structure may be
 * directly instantiated and initialised by client code, and then used in
 * subsequent `BIO_new()` calls.
 *
 * On the other hand, in OpenSSL, the `BIO_METHOD` type is opaque, meaning that
 * users cannot directly instantiate and initialise them, in the same way as in
 * BoringSSL.  Instead, the user must call `BIO_meth_new()` to create one, and
 * then set up it’s “members” by using the `BIO_meth_set_*()` functions.
 *
 * This poses a problem for the bssl-compat layer. Ideally we want client code
 * written against the BoringSSL API to build and run unchanged, which implies
 * that we must still provide the fully defined BoringSSL version of the
 * `BIO_METHOD` type, for the client code to use. However, we cannot use the
 * BoringSSL type in OpenSSL calls, because they require an `ossl_BIO_METHOD*`,
 * rather than a `BIO_METHOD*`.
 *
 * To make it work, we implement a mapping between instances of BoringSSL's
 * `BIO_METHOD*` and OpenSSL's `ossl_BIO_METHOD*` using a `std::map` protected
 * by a `std::mutex`.
 *
 * One drawback of this mapping is the potential for the `std::map` to grow
 * indefinitely in the case where client code repeatedly creates, uses then
 * deletes many BIO_METHOD instances. Since we don't have any way to know when
 * the client's `BIO_METHOD` objects go out of existence, the only safe thing
 * we can do is retain the entres in the `std::map` indefinitely.
 *
 * Luckily, the only occurrence of direct instantiation of a `BIO_METHOD` in
 * the upstream envoy source, is a single static instance (in
 * `extensions/transport_sockets/tls/io_handle_bio.cc`) which means that the
 * `std::map` will have a small and bounded size.
 */

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
static ossl_BIO_METHOD *bio_method_new(const BIO_METHOD *bsslMethod) {
  ossl_BIO_METHOD *osslMethod = ossl.ossl_BIO_meth_new(bsslMethod->type, bsslMethod->name);

  // BSSL: int (*bwrite)(BIO *, const char *, int);
  // OSSL: int BIO_meth_set_write(BIO_METHOD *biom, int (*write)(BIO *, const char *, int));
  ossl.ossl_BIO_meth_set_write(osslMethod, bsslMethod->bwrite);

  // BSSL: int (*bread)(BIO *, char *, int);
  // OSSL: int BIO_meth_set_read(BIO_METHOD *biom, int (*read)(BIO *, char *, int));
  ossl.ossl_BIO_meth_set_read(osslMethod, bsslMethod->bread);

  // BSSL: int (*bputs)(BIO *, const char *);
  // OSSL: int ossl_BIO_meth_set_puts(ossl_BIO_METHOD *biom, int (*puts)(ossl_BIO *, const char *))
  ossl.ossl_BIO_meth_set_puts(osslMethod, bsslMethod->bputs);

  // BSSL: int (*bgets)(BIO *, char *, int);
  // OSSL: int ossl_BIO_meth_set_gets(ossl_BIO_METHOD *biom, int (*gets)(ossl_BIO *, char *, int))
  ossl.ossl_BIO_meth_set_gets(osslMethod, bsslMethod->bgets);

  // BSSL: long (*ctrl)(BIO *, int, long, void *);
  // OSSL: int BIO_meth_set_ctrl(BIO_METHOD *biom, long (*ctrl)(BIO *, int, long, void *));
  ossl.ossl_BIO_meth_set_ctrl(osslMethod, bsslMethod->ctrl);

  // BSSL: int (*create)(BIO *);
  // OSSL: int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *));
  ossl.ossl_BIO_meth_set_create(osslMethod, bsslMethod->create);

  // BSSL: int (*destroy)(BIO *);
  // OSSL: int BIO_meth_set_destroy(BIO_METHOD *biom, int (*destroy)(BIO *));
  ossl.ossl_BIO_meth_set_destroy(osslMethod, bsslMethod->destroy);

  // BSSL: long (*callback_ctrl)(BIO *, int, bio_info_cb);
  // OSSL: int ossl_BIO_meth_set_callback_ctrl(ossl_BIO_METHOD *biom, long (*callback_ctrl)(ossl_BIO *, int, ossl_BIO_info_cb *))
  if (bsslMethod->callback_ctrl == nullptr) {
    ossl.ossl_BIO_meth_set_callback_ctrl(osslMethod, nullptr);
  }
  else {
    bssl_compat_fatal("BIO_METHOD::callback_ctrl is not supported");
  }

  return osslMethod;
}

/**
 * Registers the mapping between the specified BoringSSL BIO_METHOD*, and the OpenSSL ossl_BIO_METHOD*
 */
bool bio_meth_map_register(const BIO_METHOD *bsslMethod, const ossl_BIO_METHOD*osslMethod) {
  std::lock_guard<std::mutex> lock(mutex);
  auto i = map.insert(std::make_pair(bsslMethod, osslMethod));
  return i.second;
}

/*
 * Takes a BoringSSL BIO_METHOD and returns the equivalent OpenSSL BIO_METHOD
 */
const ossl_BIO_METHOD *bio_meth_map_lookup(const BIO_METHOD *bsslMethod) {
  std::lock_guard<std::mutex> lock(mutex);
  auto i = map.find(bsslMethod);

  if (i == map.end()) {
    ossl_BIO_METHOD *osslMethod = bio_method_new(bsslMethod);
    map.insert(std::make_pair(bsslMethod, osslMethod));
    return osslMethod;
  }
  else {
    return i->second;
  }
}
