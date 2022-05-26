#include <openssl/bytestring.h>
#include <openssl/asn1.h>

#include <string.h>
#include <limits.h>

#include <openssl/err.h>

#include "internal.h"

/* Convert just ASN1 INTEGER content octets to ASN1_INTEGER structure */

ASN1_INTEGER *c2i_ASN1_INTEGER(ASN1_INTEGER **a, const unsigned char **pp,
                               long len)
{
    ASN1_INTEGER *ret = NULL;
    const unsigned char *p, *pend;
    unsigned char *to, *s;
    int i;

    /*
     * This function can handle lengths up to INT_MAX - 1, but the rest of the
     * legacy ASN.1 code mixes integer types, so avoid exposing it to
     * ASN1_INTEGERS with larger lengths.
     */
    if (len < 0 || len > INT_MAX / 2) {
        OPENSSL_PUT_ERROR(ASN1, ASN1_R_TOO_LONG);
        return NULL;
    }

    if ((a == NULL) || ((*a) == NULL)) {
        if ((ret = ASN1_INTEGER_new()) == NULL)
            return (NULL);
        ret->type = V_ASN1_INTEGER;
    } else
        ret = (*a);

    p = *pp;
    pend = p + len;

    /*
     * We must OPENSSL_malloc stuff, even for 0 bytes otherwise it signifies
     * a missing NULL parameter.
     */
    s = (unsigned char *)OPENSSL_malloc((int)len + 1);
    if (s == NULL) {
        i = ERR_R_MALLOC_FAILURE;
        goto err;
    }
    to = s;
    if (!len) {
        /*
         * Strictly speaking this is an illegal INTEGER but we tolerate it.
         */
        ret->type = V_ASN1_INTEGER;
    } else if (*p & 0x80) {     /* a negative number */
        ret->type = V_ASN1_NEG_INTEGER;
        if ((*p == 0xff) && (len != 1)) {
            p++;
            len--;
        }
        i = len;
        p += i - 1;
        to += i - 1;
        while ((!*p) && i) {
            *(to--) = 0;
            i--;
            p--;
        }
        /*
         * Special case: if all zeros then the number will be of the form FF
         * followed by n zero bytes: this corresponds to 1 followed by n zero
         * bytes. We've already written n zeros so we just append an extra
         * one and set the first byte to a 1. This is treated separately
         * because it is the only case where the number of bytes is larger
         * than len.
         */
        if (!i) {
            *s = 1;
            s[len] = 0;
            len++;
        } else {
            *(to--) = (*(p--) ^ 0xff) + 1;
            i--;
            for (; i > 0; i--)
                *(to--) = *(p--) ^ 0xff;
        }
    } else {
        ret->type = V_ASN1_INTEGER;
        if ((*p == 0) && (len != 1)) {
            p++;
            len--;
        }
        OPENSSL_memcpy(s, p, (int)len);
    }

    if (ret->data != NULL)
        OPENSSL_free(ret->data);
    ret->data = s;
    ret->length = (int)len;
    if (a != NULL)
        (*a) = ret;
    *pp = pend;
    return (ret);
 err:
    OPENSSL_PUT_ERROR(ASN1, i);
    if ((ret != NULL) && ((a == NULL) || (*a != ret)))
        ASN1_INTEGER_free(ret);
    return (NULL);
}
