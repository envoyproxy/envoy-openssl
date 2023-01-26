#include <openssl/bio.h>
#include <ossl/openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/mem.h>
#include <assert.h>
#include "../crypto/internal.h"


// BIO_ctrl_get_read_request returns the number of bytes that the other side of
// |bio| tried (unsuccessfully) to read.
size_t BIO_ctrl_get_read_request(BIO *bio) {
  return ossl_BIO_ctrl_get_read_request(bio);
}

// BIO_ctrl_get_write_guarantee returns the number of bytes that |bio| (which
// must have been returned by |BIO_new_bio_pair|) will accept on the next
// |BIO_write| call.
size_t BIO_ctrl_get_write_guarantee(BIO *bio) {
  return ossl_BIO_ctrl_get_write_guarantee(bio);
}

// BIO_new_connect returns a BIO that connects to the given hostname and port.
// The |host_and_optional_port| argument should be of the form
// "www.example.com" or "www.example.com:443". If the port is omitted, it must
// be provided with |BIO_set_conn_port|.
//
// It returns the new BIO on success, or NULL on error.
BIO *BIO_new_connect(const char *host_and_optional_port) {
  return ossl_BIO_new_connect(host_and_optional_port);
}

// BIO_printf behaves like |printf| but outputs to |bio| rather than a |FILE|.
// It returns the number of bytes written or a negative number on error.
int BIO_printf(BIO *bio, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int ret = ossl_BIO_vprintf(bio, format, args);
  va_end(args);
  return ret;
}

// bio_read_full reads |len| bytes |bio| and writes them into |out|. It
// tolerates partial reads from |bio| and returns one on success or zero if a
// read fails before |len| bytes are read. On failure, it additionally sets
// |*out_eof_on_first_read| to whether the error was due to |bio| returning zero
// on the first read. |out_eof_on_first_read| may be NULL to discard the value.
static int bio_read_full(BIO *bio, uint8_t *out, int *out_eof_on_first_read,
                         size_t len) {
  int first_read = 1;
  while (len > 0) {
    int todo = len <= INT_MAX ? (int)len : INT_MAX;
    int ret = BIO_read(bio, out, todo);
    if (ret <= 0) {
      if (out_eof_on_first_read != NULL) {
        *out_eof_on_first_read = first_read && ret == 0;
      }
      return 0;
    }
    out += ret;
    len -= (size_t)ret;
    first_read = 0;
  }

  return 1;
}

// bio_read_all reads everything from |bio| and prepends |prefix| to it. On
// success, |*out| is set to an allocated buffer (which should be freed with
// |OPENSSL_free|), |*out_len| is set to its length and one is returned. The
// buffer will contain |prefix| followed by the contents of |bio|. On failure,
// zero is returned.
//
// The function will fail if the size of the output would equal or exceed
// |max_len|.
static int bio_read_all(BIO *bio, uint8_t **out, size_t *out_len,
                        const uint8_t *prefix, size_t prefix_len,
                        size_t max_len) {
  static const size_t kChunkSize = 4096;

  size_t len = prefix_len + kChunkSize;
  if (len > max_len) {
    len = max_len;
  }
  if (len < prefix_len) {
    return 0;
  }
  *out = OPENSSL_malloc(len);
  if (*out == NULL) {
    return 0;
  }
  OPENSSL_memcpy(*out, prefix, prefix_len);
  size_t done = prefix_len;

  for (;;) {
    if (done == len) {
      OPENSSL_free(*out);
      return 0;
    }
    const size_t todo = len - done;
    assert(todo < INT_MAX);
    const int n = BIO_read(bio, *out + done, todo);
    if (n == 0) {
      *out_len = done;
      return 1;
    } else if (n == -1) {
      OPENSSL_free(*out);
      return 0;
    }

    done += n;
    if (len < max_len && len - done < kChunkSize / 2) {
      len += kChunkSize;
      if (len < kChunkSize || len > max_len) {
        len = max_len;
      }
      uint8_t *new_buf = OPENSSL_realloc(*out, len);
      if (new_buf == NULL) {
        OPENSSL_free(*out);
        return 0;
      }
      *out = new_buf;
    }
  }
}

// BIO_read_asn1 reads a single ASN.1 object from |bio|. If successful it sets
// |*out| to be an allocated buffer (that should be freed with |OPENSSL_free|),
// |*out_size| to the length, in bytes, of that buffer and returns one.
// Otherwise it returns zero.
//
// If the length of the object is greater than |max_len| or 2^32 then the
// function will fail. Long-form tags are not supported. If the length of the
// object is indefinite the full contents of |bio| are read, unless it would be
// greater than |max_len|, in which case the function fails.
//
// If the function fails then some unknown amount of data may have been read
// from |bio|.
int BIO_read_asn1(BIO *bio, uint8_t **out, size_t *out_len, size_t max_len) {
  uint8_t header[6];

  static const size_t kInitialHeaderLen = 2;
  int eof_on_first_read;
  if (!bio_read_full(bio, header, &eof_on_first_read, kInitialHeaderLen)) {
    if (eof_on_first_read) {
      // Historically, OpenSSL returned |ASN1_R_HEADER_TOO_LONG| when
      // |d2i_*_bio| could not read anything. CPython conditions on this to
      // determine if |bio| was empty.
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_HEADER_TOO_LONG);
    } else {
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_NOT_ENOUGH_DATA);
    }
    return 0;
  }

  const uint8_t tag = header[0];
  const uint8_t length_byte = header[1];

  if ((tag & 0x1f) == 0x1f) {
    // Long form tags are not supported.
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_DECODE_ERROR);
    return 0;
  }

  size_t len, header_len;
  if ((length_byte & 0x80) == 0) {
    // Short form length.
    len = length_byte;
    header_len = kInitialHeaderLen;
  } else {
    const size_t num_bytes = length_byte & 0x7f;

    if ((tag & 0x20 /* constructed */) != 0 && num_bytes == 0) {
      // indefinite length.
      if (!bio_read_all(bio, out, out_len, header, kInitialHeaderLen,
                        max_len)) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_NOT_ENOUGH_DATA);
        return 0;
      }
      return 1;
    }

    if (num_bytes == 0 || num_bytes > 4) {
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_DECODE_ERROR);
      return 0;
    }

    if (!bio_read_full(bio, header + kInitialHeaderLen, NULL, num_bytes)) {
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_NOT_ENOUGH_DATA);
      return 0;
    }
    header_len = kInitialHeaderLen + num_bytes;

    uint32_t len32 = 0;
    for (unsigned i = 0; i < num_bytes; i++) {
      len32 <<= 8;
      len32 |= header[kInitialHeaderLen + i];
    }

    if (len32 < 128) {
      // Length should have used short-form encoding.
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_DECODE_ERROR);
      return 0;
    }

    if ((len32 >> ((num_bytes-1)*8)) == 0) {
      // Length should have been at least one byte shorter.
      OPENSSL_PUT_ERROR(ASN1, ASN1_R_DECODE_ERROR);
      return 0;
    }

    len = len32;
  }

  if (len + header_len < len ||
      len + header_len > max_len ||
      len > INT_MAX) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_TOO_LONG);
    return 0;
  }
  len += header_len;
  *out_len = len;

  *out = OPENSSL_malloc(len);
  if (*out == NULL) {
    OPENSSL_PUT_ERROR(ASN1, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  OPENSSL_memcpy(*out, header, header_len);
  if (!bio_read_full(bio, (*out) + header_len, NULL, len - header_len)) {
    OPENSSL_PUT_ERROR(ASN1, ASN1_R_NOT_ENOUGH_DATA);
    OPENSSL_free(*out);
    return 0;
  }

  return 1;
}

// BIO_read attempts to read |len| bytes into |data|. It returns the number of
// bytes read, zero on EOF, or a negative number on error.
int BIO_read(BIO *bio, void *data, int len) {
  return ossl_BIO_read(bio, data, len);
}

// BIO_reset resets |bio| to its initial state, the precise meaning of which
// depends on the concrete type of |bio|. It returns one on success and zero
// otherwise.
int BIO_reset(BIO *bio) {
  return ossl_BIO_reset(bio);
}

// BIO_should_read returns non-zero if |bio| encountered a temporary error
// while reading (i.e. EAGAIN), indicating that the caller should retry the
// read.
int BIO_should_read(const BIO *bio) {
  return ossl_BIO_should_read(bio);
}

// BIO_should_write returns non-zero if |bio| encountered a temporary error
// while writing (i.e. EAGAIN), indicating that the caller should retry the
// write.
int BIO_should_write(const BIO *bio) {
  return ossl_BIO_should_write(bio);
}

// BIO_shutdown_wr marks |bio| as closed, from the point of view of the other
// side of the pair. Future |BIO_write| calls on |bio| will fail. It returns
// one on success and zero otherwise.
int BIO_shutdown_wr(BIO *bio) {
  return ossl_BIO_shutdown_wr(bio);
}

int BIO_snprintf(char *buf, size_t n, const char *format, ...) {
  va_list args;
  va_start(args, format);
  int ret = ossl_BIO_vsnprintf(buf, n, format, args);
  va_end(args);
  return ret;
}

// BIO_write writes |len| bytes from |data| to |bio|. It returns the number of
// bytes written or a negative number on error.
int BIO_write(BIO *bio, const void *data, int len) {
  return ossl_BIO_write(bio, data, len);
}
