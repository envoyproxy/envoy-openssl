# Envoy OpenSSL Integration Design Document

## Problem Statement

Various corporations require an OpenSSL version of Envoy.  The upstream version of Envoy is tightly coupled to BoringSSL.  The overhead in producing an OpenSSL compliant version for each release needs to be reduced while maintaining functionality and security.

## Introduction

This document outlines the problems with providing an OpenSSL compliant version of Envoy and presents an overview of how the problem may be resolved.  This document is an extension/elaboration of the work originally identified in the “Roadmap #1” document located in the upstream envoy-openssl repository.

An ideal situation of a pluggable cryptographic/TLS code/module given a provider (BoringSSL/OpenSSL) is impractical given code complexity and current release level functionality.  Additionally, encapsulating all relevant functionality for mapping BoringSSL calls into a single library is unlikely to be completely possible.

The solution to the problem will likely include 
- some upstream modifications (minimising impact, and avoiding `#ifdefs` )
- some custom downstream classes (for example, asynchronous handshaker classes and QUIC extension)
- together with the addition of a library for mapping BoringSSL to OpenSSL that also includes aggregation of functionality where possible.

## Rationale

Envoy Proxy is tightly coupled with BoringSSL[^1] , a Google library that is a subset of [OpenSSL](https://www.openssl.org/). An OpenSSL version is, for several organisations, critical due to corporate standards which include mandatory requirements for OpenSSL with FIPS[^f].  Maintaining a fork of Envoy that replaces BoringSSL with OpenSSL represents a significant non-trivial and increasing maintenance effort.  As Envoy progresses and with refactoring and use of BoringSSL and Quic [#reference] the feasibility of an alternative to refactoring would be ideal.

![BoringSSL problem](https://github.com/envoyproxy/envoy-openssl/blob/main/docs/BoringSSL-problem.png)

The ServiceMesh/Maistra version of Envoy is an OpenSSL implementation replacing the BoringSSL transport socket layer.  The OpenSSL library is dynamically linked, preserving cryptographic compliance with FIPS 140-2[^f2] and soon FIPS 140-3[^f3].

The current synchronisation process is to periodically (manually) merge a release branch of [envoyproxy/envoy](https://github.com/envoyproxy/envoy) into a [maistra/envoy](https://github.com/maistra/envoy) release branch.  Resolving conflicts, adjusting BoringSSL calls to be OpenSSL compatible (or removing those that can't be supported), confirming changes and testing.  

Ideally, an alternative to refactoring that preserves the upstream code limiting refactoring for OpenSSL , has compatibility with code and function while minimising the risk of introducing errors or reduced functionality.  This will allow for quicker delivery on an OpenSSL version with each upstream release.

This document outlines the problems with such an approach with the view to quantifying feasibility.

## Design Goals
Ideally an implementation should:
- Reduce the release times for OpenSSL version of Envoy 
  - Reduce the maintenance overhead
  - Reduce the risk of bugs and vulnerabilities
  - Minimise impact on upstream code
  - Increase test coverage and quality as we grow the bssl wrapper.
  - Re-use any BoringSSL test cases where possible
  - Gapnalysis in tests with respective implementations.
- Increase engagement with upstream and external contributors
- Maintain functionality with upstream Envoy 
- No increased risk in security or vulnerability by using OpenSSL as an alternative to BoringSSL
- Specify a “definition of completion” that includes reviewing a ported api call:
  - functionality is complete and well defined
  - is documented
  - has sufficient test coverage as proof completeness.

## Risks
- There are no stability guarantees for the BoringSSL apis
- Ideally upstream changes should be introduced to use API calls instead of directly working on some structures.   Although there’s no guarantee that the upstream will accept such changes. 
- Performance: There may be a need to bridge threading models in the handshaker code. It may be that it will not be feasible to transparently bridge this difference between libraries without incurring an unacceptable performance penalty (respecting asynchronous call model).
- Future churn: new changes to Envoy, as well as updates to dependencies, may bring in new calls to BoringSSL. This will mean more work on the bridge layer to extend it to support that.
	
### Complications

The often asked question is "given the complications in maintaining an OpenSSL version, why don't we just use BoringSSL?".    In short, because there is a corporate standard for [FIPs](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md) with OpenSSL.   Certification is not trivial and FIPS-140-3 has specific requirements regarding algorithms and interfaces.

Given the complexity of Envoy functionality and coupling to BoringSSL there are several complications arising from providing an OpenSSL interface:

a. BoringSSL Header Files, in some cases are different from OpenSSL and will require some header file aliasing for compatibility.  The bssl-wrapper code has examples of this.  The `include/openssl/x509*` and `include/openssl/ossl_type.h` files are other examples.  
b. Not all functionality that depends on BoringSSL is simply mapped to OpenSSL.
	- The BoringSSL implementation of the constructor for `Envoy::Extensions::TransportSockets::Tls::ContextImpl` relies on a loop to process TLS Contexts to process multiple certificates, the OpenSSL case doesn't.  This leads to functionality that is externalised into the `Context` implementation for BoringSSL.   The Context class is one of the most complex classes that are affected by refactoring for OpenSSL.
	- OpenSSL has no implementation for `SSL_ERROR_WANT_PRIVATE_KEY_OPERATION` used in `ssl_handshaker.cc`.
c. In the opposite direction, there is not always a simple mapping from OpenSSL to BoringSSL as exemplified in the case of `#define BORINGSSL_MAKE_DELETER(type, deleter)` in bssl-wrapper [bssl-wrapper.h](https://github.com/maistra/bssl_wrapper/blob/maistra-2.0/bssl_wrapper/bssl_wrapper.h)
d. There are cases in the OpenSSL implementation that should be removed from the Envoy code base and placed in the compatibility library.   A simple example of this is the [openssl_impl](https://github.com/maistra/envoy/blob/maistra-2.2/source/extensions/transport_sockets/tls/openssl_impl.cc) files in Maistra Envoy.  Generally code that is not Envoy dependent and relates to OpenSSL can be moved into a library to promote re-use and the separation of concerns.
e. Some Envoy dependencies also depend on BoringSSL; a compatibility library would remove the need for refactoring dependencies.
  While these have been patched to support OpenSSL there may be extensions or future dependencies that arise that are BoringSSL dependent which also represent an increased testing burden.
	- https://github.com/grpc/grpc
	- https://github.com/google/jwt_verify_lib 
Q: Does fips require that all dependencies use openssl? A: Suspect YES.
f. Cases where callbacks are in Envoy code that represent complications in achieving callbacks from within a library [#reference]. In the tls ContextImpl class, this is heavily refactored for OpenSSL.
g. Support for non x64 architecture with hardware support for example System Z.
h. Support for asynchronous and opaque private keys e.g. CryptoMB, unsupported OpenSSL methods:
  - SSL_CTX_set_chain_and_key()
  - SSL_chain_and_key()
  - SSL_set_private_key_method()
  - SSL_set1_delegated_credential()
i.  As of 1.1.0, OpenSSL moved a number of structures to be opaque, requiring specific API calls.  Any instances of Envoy usage of these structures will imply another point of maintenance of differences. It may be prudent to rework these upstream areas to improve compatibility ([example `int io_handle_new(BIO* bio)`](https://github.com/maistra/envoy/blob/maistra-2.2/source/extensions/transport_sockets/tls/io_handle_bio.cc)).  Where possible advocate for updates to BoringSSL for API wrapper for structure access in line with OpenSSL and submit respective updates to Envoy.
j.  BoringSSL is a subset of OpenSSL and there are some complications in maintaining compatibility:
  - "There are no guarantees of API or ABI stability with this code (BoringSSL)"[^2] 
  - "There are implementation issues associated with differences[^5] between OpenSSL and BoringSSL relating to return values and threading both in Envoy and OpenSSL."
  - Any Envoy dependent libraries that use BoringSSL have to be extended to support OpenSSL.  
k. Specific blocks of code in Envoy are flagged for FIPS compliance.
l. `#ifdef OPENSSL_IS_BORINGSSL` usage in code (likely extension of usage upstream but delegation to library where possible)
m. `#ifdef BORINGSSL_FIPS` usage in code (FIPS specific guards must be supported)`
i. RHEL 9 has OpenSSL 3.0.0-0.beta2.  Check compatibility with 1.1.1.

## Implementation

Currently, code is heavily refactored and merged for a release.  Instead, a re-base for each release with application of patches and dependence on a well defined compatibility layer reduces the risk of introducing regressions and incompatibilities and vulnerabilities.  A reduction in refactoring for OpenSSL is mandatory.

Aim for release v1.22 of Envoy working with OpenSSL compatibility support.  This will likely exclude Quic support initially although an alternative to Envoy Quic is being considered as a possible alternative "plugin".

A hybrid approach would provide:
A compatibility library that encapsulates OpenSSL functionality mapping the BoringSSL API
Separate code for OpenSSL where code can’t be abstracted into a library
Patch files to allow for modification of each release.

Increase test coverage and quality as we enhance the bssl wrapper. We may be able to:
Re-use any boringssl unit tests against its own api’s
Or add new unit tests to cater for any testing gaps
Thread/spam test the handshaking code 

The impact on [upstream code](https://github.com/envoyproxy/envoy) has to be minimal, limited to use of `#ifdef` modifications when absolutely necessary.    As much as practically possible any differences are totally contained in separate runtime libraries and patch files that can be applied to an upstream release for a build.

The number of changes required to upstream Envoy to make crypto/tls "pluggable" is impractical and represents high risk; there are many instances of varied complexity that use the BoringSSL functionality.

The compatibility library will provide wrapper functions to 
	a. Map BoringSSL functions to OpenSSL functions essentially encapsulating behaviour to preserve BoringSSL API compatibility.  This in part represents an inverse mapping of the work outlined in the [BoringSSL, Porting from OpenSSL to BoringSSL](https://boringssl.googlesource.com/boringssl/+/HEAD/PORTING.md) and [Project Mu, Porting from OpenSSL to BoringSSL](https://microsoft.github.io/mu/dyn/mu_tiano_plus/CryptoPkg/Library/OpensslLib/openssl/boringssl/PORTING/) 
	b. Extend on the work of the [bssl-wrapper](https://github.com/maistra/bssl_wrapper) to accommodate added API's ([CBS and CBB is a simple example](https://commondatastorage.googleapis.com/chromium-boringssl-docs/bytestring.h.html)) with added Test cases.
	c. The bssl-wrapper code will form the basis of the new compatibility library.

The proposed implementation is to extend the concept of the [bssl-wrapper](https://github.com/maistra/bssl_wrapper), with the view to as much as practically possible provide API and functional equivalency with BoringSSL as used in Envoy.   Then maintaining an OpenSSL version of Envoy does not represent a likely refactoring and possibly redevelopment of related TLS/Crypto calls for each release. This will be a shared library that can be referenced in the bazel build files as a functional alternative to BoringSSL.

The complications listed previously indicate that this solution will not be perfect.  Only those API functions used by Envoy will be supported.  Even with this design there will likely be a residual set of classes that are flagged as "refactor only" due to complexity.  Cases of asynchronous callbacks are likely being candidates for this treatment.

The end result will likely be an extended bssl-wrapper with a reduced refactoring work per release.  A clean isomorphism from BoringSSL to OpenSSL even with accommodations for the complications is likely unrealistic. 

The implementation will provide a BoringSSL to OpenSSL bridge accounting for :
1. Differences in API return codes, types and error messages as per  [BoringSSL, Porting from OpenSSL to BoringSSL](https://boringssl.googlesource.com/boringssl/+/HEAD/PORTING.md) and [Project Mu, Porting from OpenSSL to BoringSSL](https://microsoft.github.io/mu/dyn/mu_tiano_plus/CryptoPkg/Library/OpensslLib/openssl/boringssl/PORTING/) 
2. Only those BoringSSL/OpenSSL calls used in Envoy.
3. Provide wrapper functionality that aggregates a series of OpenSSL calls to emulate BoringSSL calls where needed.  Ensuring that no cryptographic functionality is specifically coded.  The interface has to provide call wrapping not cryptographic implementations.
4. Add an OpenSSL compatible alternative to QUIC as provided by Envoy.  This is one area where upstream changes would be more efficient, although patch files and custom classes maintained separate to upstream would likely be the result.
5. OpenSSL support for Intel's IPP (Integrated Performance Primitives) crypto library (currently has BoringSSL support)
6. BoringSSL asynchronous [private key operations](https://github.com/envoyproxy/envoy/issues/6248) 
7. Performance impact of library calls to wrap BoringSSL calls.

# References
[^1]: https://github.com/google/boringssl 
[^2]: https://www.chromium.org/Home/chromium-security/boringssl/
[^3]: https://boringssl.googlesource.com/boringssl/
[^4]: https://www.interserver.net/tips/kb/openssl-vs-boringssl-boringssl-install-boringssl/
[^5]: https://www.openssl.org/docs/fips.html
[^6]: [Porting from OpenSSL to BoringSSL](https://boringssl.googlesource.com/boringssl/+/HEAD/PORTING.md) 
[^f]: https://www.nist.gov/standardsgov/compliance-faqs-federal-information-processing-standards-fips
[^f2]: https://csrc.nist.gov/publications/detail/fips/140/2/final
[^f3]: https://csrc.nist.gov/publications/detail/fips/140/3/final

## History 
- [Google unveils independent “fork” of OpenSSL called “BoringSSL”](https://arstechnica.com/information-technology/2014/06/google-unveils-independent-fork-of-openssl-called-boringssl/) 
- [Heartbleed](https://heartbleed.com/)
- [Google unveils BoringSSL](https://arstechnica.com/information-technology/2014/06/google-unveils-independent-fork-of-openssl-called-boringssl/)
- Envoy-OpenSSL Roadmap #1

