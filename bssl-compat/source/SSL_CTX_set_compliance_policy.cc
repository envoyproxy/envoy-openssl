#include <openssl/ssl.h>
#include <ossl.h>




int SSL_CTX_set_compliance_policy(SSL_CTX *ctx,
                                  enum ssl_compliance_policy_t policy) {
  switch (policy) {
//     case ssl_compliance_policy_fips_202205:
//       return fips202205::Configure(ctx);
//     case ssl_compliance_policy_wpa3_192_202304:
//       return wpa202304::Configure(ctx);
//     case ssl_compliance_policy_cnsa_202407:
//       return cnsa202407::Configure(ctx);
    default:
      return 0;
  }
}
