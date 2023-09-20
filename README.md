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

After initial checkout, initialize and update submodules for Envoy and
BoringSSL:
```
git submodule update --init --depth=1
```

For a standalone build of the `bssl-compat` library, see
[bssl-compat README](bssl-compat/README.md).

For a full build of envoy on the `bssl-compat` library, start by running the `run-build-container.sh` script:
```
./run-build-container.sh
```

This script pulls the upstream envoy builder image (which may take some time) and then runs an interactive bash prompt.

Then, to build envoy simply run the following:

```
bazel build @envoy//:envoy
```

## Testing


## License

The Envoy OpenSSL Extensions project is governed by the Apache License, Version
2.0. See the [LICENSE](LICENSE) file for the full license text.

## More info

 - [team meetings](https://docs.google.com/document/d/1OPLMmArPtiHjBoLxCRZSBT8oxlRcSAlWnTuHV-tLPW8/edit?usp=sharing)
 
