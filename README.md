![Envoy Logo](https://github.com/envoyproxy/artwork/blob/main/PNG/Envoy_Logo_Final_PANTONE.png)

[Cloud-native high-performance edge/middle/service proxy](https://www.envoyproxy.io/)

Envoy is hosted by the [Cloud Native Computing Foundation](https://cncf.io) (CNCF). If you are a
company that wants to help shape the evolution of technologies that are container-packaged,
dynamically-scheduled and microservices-oriented, consider joining the CNCF. For details about who's
involved and how Envoy plays a role, read the CNCF
[announcement](https://www.cncf.io/blog/2017/09/13/cncf-hosts-envoy/).

## Envoy OpenSSL

This repository is a copy of the regular [envoyproxy/envoy](https://github.com/envoyproxy/envoy)
repository, with additions & modifications that enable Envoy to be built on OpenSSL rather than
BoringSSL.

This README deals with the specifics of building Envoy on OpenSSL, whereas the README for the
regular Envoy can be found [here](https://github.com/envoyproxy/envoy/blob/main/README.md). 

## Building

The process for building envoy-openssl is very similar to building regular envoy, wherever possible
reusing the same builder image and the same scripts, and the same steps.

Building the envoy-openssl project is done in a build container which is based on the regular envoy
build container, but with some additional requirements installed, including OpenSSL 3.0.x. This build
container is launched using the the `openssl/run_envoy_docker.sh` script, which handles some openssl
specific config and then passes control to the regular `ci/run_envoy_docker.sh` script.

Building & running tests, and building the envoy binary itself, is done using the `openssl/do_ci.sh`
script, which handles some openssl specific config and then passes control to the regular `ci/do_ci.sh`
script.

Although the regular `ci/do_ci.sh` script supports many options for building/testing different variants of envoy,
including the use of various sanitizers, the envoy-openssl project has so far only been built and tested
using the `debug` options described below. Any other `do_ci.sh` options that are described
in the regular envoy documentation [here](https://github.com/envoyproxy/envoy/tree/main/ci#readme)
_should_ work but have not been tested.

To build the envoy executable and run specified tests, in debug mode:
```bash
./openssl/run_envoy_docker.sh './openssl/do_ci.sh debug //test/extensions/transport_sockets/tls/...'
```

To build just the envoy executable, in debug mode:
```bash
./openssl/run_envoy_docker.sh './openssl/do_ci.sh debug.server_only'
```

After running these build commands, the resulting envoy executable can be found in the host's file system at `/tmp/envoy-docker-build/envoy/x64/source/exe/envoy/envoy`. Note that you can place the build artifacts at a different location on the host by setting ENVOY_DOCKER_BUILD_DIR environment variable _before_ invoking the `openssl/run_envoy_docker.sh` script. For example, running the following command would put the build artifact in `/build/envoy/x64/source/exe/envoy/envoy`:
```bash
ENVOY_DOCKER_BUILD_DIR=/build ./openssl/run_envoy_docker.sh './openssl/do_ci.sh debug.server_only'
```

Note that, in addition to running the `do_ci.sh` script directly in batch mode, as done in the examples
above, the `openssl/run_envoy_docker.sh` script can also be used to run an interactive shell, which
can be more convenient when repeatedly buildin/running tests:

```bash
host $ ./openssl/run_envoy_docker.sh bash

container $ ./openssl/do_ci.sh debug //test/extensions/transport_sockets/tls/...
container $ ./openssl/do_ci.sh debug //test/common/runtime/...
```

## Running Envoy

When running the envoy executable in the build container, by default it will fail, with the following error
message, bacause the build image only has OpenSSL 1.1.x installed, but the envoy executable needs to load
and use OpenSSL 3.0.x libraries:

```bash
$ /build/envoy/x64/source/exe/envoy/envoy --version
Expecting to load OpenSSL version 3.0.x but got 1.1.6
```

To ensure that envoy loads the OpenSSL 3.0.x libraries, their path needs to be prepended to `LD_LIBRARY_PATH` before it is executed:

```bash
$ LD_LIBRARY_PATH=$OPENSSL_ROOT_DIR/lib64:$LD_LIBRARY_PATH /build/envoy/x64/source/exe/envoy/envoy --version
/build/envoy/x64/source/exe/envoy/envoy  version: dcd3e1c50ace27b14441fc8b28650b62c0bf2dd2/1.26.8-dev/Modified/DEBUG/BoringSSL
```
