# Java Buildpack Client Certificate Mapper

| Workflow | Status |
| -------- | ------ |
| CI | [![CI](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml) |
| Release | [![Release](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml) |

The `java-buildpack-client-certificate-mapper` is a Servlet filter that maps the `X-Forwarded-Client-Cert` header to the `javax.servlet.request.X509Certificate` (javax) or `jakarta.servlet.request.X509Certificate` (jakarta) Servlet attribute.

It supports both the structured XFCC format (as produced by Cloud Foundry's Gorouter) and raw Base64/URL-encoded certificate headers (as produced by nginx).

## Download

Pre-built jars are available on the [Releases page](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/releases):

- **Releases** — tagged versions (e.g. `v2.0.2`)
- **Snapshot** — latest build from `main` (pre-release, updated on every push)

## Configuration

All options are controlled via JVM system properties.

### `org.cloudfoundry.router.certificate.cache.enabled`

Enables or disables certificate caching. When enabled, parsed `X509Certificate` objects are cached and reused across requests for the same certificate, avoiding repeated DER/PEM parsing.

| Value | Behaviour |
|-------|-----------|
| `true` _(default)_ | Caching enabled |
| `false` | Caching disabled; every request parses the certificate from scratch |

### `org.cloudfoundry.router.certificate.cache.raw.key`

Applies only to raw (non-XFCC) headers. Controls how the cache key is derived from the raw header value. Computing the key is cheaper than creating a full `X509Certificate` object on every request.

| Value | Behaviour |
|-------|-----------|
| `sha256` _(default)_ | SHA-256 hex digest of the raw header value — compact key, negligible collision risk |
| `full` | Full raw header value — zero collision risk, but stores a multi-KB string per cache entry |

For XFCC-format headers the `Hash=` field provided by the router is used as the cache key directly (no computation needed).

### `org.cloudfoundry.router.certificate.header.remove`

When enabled, the `X-Forwarded-Client-Cert` header is hidden from all downstream filters and servlets after the certificate has been parsed and stored as a request attribute. This prevents large PEM/DER certificate values from being needlessly processed by downstream infrastructure such as:

- Distributed tracing filters (OpenTelemetry, Micrometer Tracing / Spring Cloud Sleuth)
- Request logging filters (`CommonsRequestLoggingFilter`, Tomcat `RequestDumperValve`)
- Security filters that iterate all headers

The wrapper is only created when the header is actually present on the request, so there is no overhead for requests without a client certificate.

| Value | Behaviour |
|-------|-----------|
| `false` _(default)_ | Header passed through unchanged |
| `true` | Header hidden from downstream filters via `HttpServletRequestWrapper` |

> **Note:** Hiding the header does not free the underlying string memory during the request — it prevents downstream code from reading it. Memory is reclaimed when the request completes and the original request object is GC'd.

## Development

The project requires Java 8. To build and test from source:

```shell
$ ./mvnw clean package
```

## CI / Workflows

| Workflow | Trigger | Description |
| -------- | ------- | ----------- |
| **CI** | push to `main`, pull requests, manual | Builds and runs all tests. On push to `main` (after tests pass) also publishes the jar to the rolling snapshot release. |
| **Release** | manual (`workflow_dispatch`) | Bumps to release version, tags `vX.Y.Z`, creates a GitHub Release with the jar attached, then advances to the next SNAPSHOT version. |

All workflows can be triggered manually from **Actions → select workflow → Run workflow** in the GitHub UI.

## Contributing
[Pull requests][u] and [Issues][e] are welcome.

## License
This project is released under version 2.0 of the [Apache License][l].

[e]: https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
