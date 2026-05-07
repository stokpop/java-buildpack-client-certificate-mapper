# Java Buildpack Client Certificate Mapper

| Job | Status
| --- | ------
| `unit-test-7` | [![unit-test-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/client-certificate-mapper/jobs/unit-test-7/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/client-certificate-mapper/jobs/unit-test-7)
| `unit-test-8` | [![unit-test-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/client-certificate-mapper/jobs/unit-test-8/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/client-certificate-mapper/jobs/unit-test-8)
| `deploy` | [![deploy-master](https://java-experience.ci.springapps.io/api/v1/teams/java-experience/pipelines/client-certificate-mapper/jobs/deploy/badge)](https://java-experience.ci.springapps.io/teams/java-experience/pipelines/client-certificate-mapper/jobs/deploy)

The `java-buildpack-client-certificate-mapper` is a Servlet filter that maps the `X-Forwarded-Client-Cert` (XFCC) header to the `javax.servlet.request.X509Certificate` / `jakarta.servlet.request.X509Certificate` Servlet attribute.

It supports both the structured XFCC format (as produced by Cloud Foundry's Gorouter) and raw Base64/URL-encoded certificate headers (as produced by nginx).

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
The project depends on Java 7.  To build from source, run the following:

```shell
$ ./mvnw clean package
```

## Contributing
[Pull requests][u] and [Issues][e] are welcome.

## License
This project is released under version 2.0 of the [Apache License][l].

[e]: https://github.com/cloudfoundry/client-certificate-mapper/issues
[l]: https://www.apache.org/licenses/LICENSE-2.0
[u]: https://help.github.com/articles/using-pull-requests
