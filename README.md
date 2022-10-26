![Envoy Logo](https://github.com/envoyproxy/artwork/blob/main/PNG/Envoy_Logo_Final_PANTONE.png)
              

# Envoy OpenSSL Extensions

The Envoy OpenSSL Extensions project hosts extensions for building
[Envoy](https://github.com/envoyproxy/envoy) purely with OpenSSL.

OpenSSL is supported by providing a compatiblity library and a set of TLS related classes that track upstream functionality using OpenSSL rather than BoringSSL.

[![Slack](https://img.shields.io/badge/slack-join%20chat-e01563.svg?logo=slack)](https://envoyproxy.slack.com/archives/CS2DANSRX)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Documentation

- [Analysis](docs/analysis.md)

## Repository Structure


## Compatiblity Library


## Classes


## Extensions


## Building

For a standalone build of the library, see
[bssl-compat README](bssl-compat/README.md).

In order to start building the Envoy handshaker extension, first install
Bazel. [Bazelisk](https://github.com/bazelbuild/bazelisk/blob/master/README.md)
is a user-friendly launcher for Bazel, install a suitable
[release](https://github.com/bazelbuild/bazelisk/releases) for the desired
platform. Clang is strongly recommended for a successful build.

After installing clang and Bazelisk/Bazel, build Envoy handshaker with:
```
CC=clang CXX=clang++ bazel build --config=clang :envoy
```

## Testing


## License

The Envoy OpenSSL Extensions project is governed by the Apache License, Version
2.0. See the [LICENSE](LICENSE) file for the full license text.

## More info

 - [team meetings](https://docs.google.com/document/d/1OPLMmArPtiHjBoLxCRZSBT8oxlRcSAlWnTuHV-tLPW8/edit?usp=sharing)
 
