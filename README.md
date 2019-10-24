![Envoy Logo](https://github.com/envoyproxy/artwork/blob/master/PNG/Envoy_Logo_Final_PANTONE.png)

# Envoy OpenSSL Extensions

The Envoy OpenSSL Extensions project hosts extensions for building
[Envoy](https://github.com/envoyproxy/envoy) purely with OpenSSL.

[![Azure Pipeline](https://img.shields.io/azure-devops/build/cncf/d1341aaf-5711-4800-816d-4295da428269/12)](https://dev.azure.com/cncf/envoy-openssl/_build?definitionId=12)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Building

To build OpenSSL-enabled Envoy run the following command.

```console
$ bazel build //:envoy
```

If you need OpenSSL dynamically linked to Envoy then re-map `@boringssl` to
`@openssl_shared` by editing the [WORKSPACE](WORKSPACE) file.

## License

The Envoy OpenSSL Extensions project is governed by the Apache License, Version
2.0. See the [LICENSE](LICENSE) file for the full license text.
