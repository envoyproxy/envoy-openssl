![Envoy Logo](https://github.com/envoyproxy/artwork/blob/master/PNG/Envoy_Logo_Final_PANTONE.png)

# Envoy OpenSSL Extensions

The Envoy OpenSSL Extensions project hosts extensions for building
[Envoy](https://github.com/envoyproxy/envoy) purely with OpenSSL.

## License

The Envoy OpenSSL Extensions project is governed by the Apache License, Version
2.0. See the [LICENSE](LICENSE) file for the full license text.

To build OpenSSL-enabled Envoy run

```
$ CXXFLAGS="-DENVOY_SSL_VERSION=\\\"OpenSSL\\\"" bazel build //:envoy --define boringssl=disabled
```

If you need OpenSSL dynamically linked to Envoy then re-map `@boringssl` to
`@openssl_shared` by editing the `WORKSPACE` file.

