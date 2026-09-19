# Java Buildpack Client Certificate Mapper

| Workflow | Status |
| -------- | ------ |
| CI | [![CI](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/ci.yml) |
| Release | [![Release](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml/badge.svg)](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/actions/workflows/release.yml) |

A Servlet filter that maps the [`X-Forwarded-Client-Cert`][xfcc] (XFCC) header set by a fronting proxy to the standard `javax.servlet.request.X509Certificate` / `jakarta.servlet.request.X509Certificate` request attribute, so your app reads the client certificate the same way it would behind direct mTLS.

- Accepts base64-encoded DER and URL-encoded PEM certificates (as produced by nginx, and by CF Gorouter with `xfcc_format: raw`), and the structured [Envoy XFCC field format][xfcc] (`Hash=`, `Cert=`, `Subject=`; as produced by Envoy, and by CF Gorouter with `xfcc_format: envoy`).
- Also exposes the Cloud Foundry app/space/org identity parsed from the Subject DN, so apps behind an mTLS domain can identify the caller even when no full certificate is forwarded.
- Your application code does not need to depend on any class from this library.

> **Trust boundary:** this filter maps the header verbatim. It does **not** verify certificate trust, validity, or proof of possession -- those come entirely from the proxy that terminated the mTLS connection and set the header. The mapped attributes are trustworthy only if requests can reach your app exclusively via that proxy. See [docs/TRUST-BOUNDARY.md](docs/TRUST-BOUNDARY.md).

## Getting started

On Cloud Foundry with the Java buildpack, the jar is added to your application automatically -- nothing to do.

To add it yourself, take a jar from the [Releases page](https://github.com/cloudfoundry/java-buildpack-client-certificate-mapper/releases) -- tagged releases such as `v2.1.0`, or **Snapshot** for the latest build from `main`.

Maven Central carries the older `2.0.1` release; newer versions are published as GitHub Releases only:

```xml
<dependency>
    <groupId>org.cloudfoundry</groupId>
    <artifactId>java-buildpack-client-certificate-mapper</artifactId>
    <version>2.0.1</version>
</dependency>
```

The filter registers itself -- no `web.xml` entry or `@Bean` needed:

- **Servlet containers (javax and jakarta):** via `ServletContainerInitializer`, mapped to `/*` for all dispatcher types.
- **Spring Boot:** via auto-configuration, at `Ordered.HIGHEST_PRECEDENCE`, active only when running on Cloud Foundry (`@ConditionalOnCloudPlatform(CLOUD_FOUNDRY)`).

## Settings

All options are JVM system properties.

| Property | Default | What it does |
| --- | --- | --- |
| `org.cloudfoundry.router.certificate.cache.enabled` | `true` | Cache parsed certificates and reuse them across requests, avoiding a repeated DER/PEM parse. |
| `org.cloudfoundry.router.certificate.cache.size` | `128` | Entries per cache generation; at most `2 x size` cached certificates (~1 MB for CF-sized headers at the default). |
| `org.cloudfoundry.router.certificate.header.hide` | `false` | Hide the XFCC header from downstream filters and servlets after parsing. |

See [Configuration](#configuration) below for when to change these, and [docs/PERFORMANCE.md](docs/PERFORMANCE.md) for measurements.

## Usage

### Read the client certificate

Use the `jakarta.` attribute name on Jakarta Servlet containers (Tomcat 10+, Spring Boot 3+) or the `javax.` name on older containers:

```java
X509Certificate[] chain =
    (X509Certificate[]) request.getAttribute("jakarta.servlet.request.X509Certificate");
if (chain != null && chain.length > 0) {
    X509Certificate clientCert = chain[0]; // leaf certificate
    clientCert.checkValidity();            // optional: the filter does not enforce validity
}
```

Spring MVC controllers can inject it directly with `@RequestAttribute`:

```java
@GetMapping("/whoami")
String whoami(@RequestAttribute("jakarta.servlet.request.X509Certificate")
              X509Certificate[] chain) {
    return chain[0].getSubjectX500Principal().getName();
}
```

### Read CF identity without the full certificate

When the router forwards only `Hash=` and `Subject=` -- as CF Gorouter does on an mTLS domain configured with `xfcc_format: envoy` -- no `X509Certificate` is available, but the filter still parses the CF identity from the Subject DN:

```java
String appGuid   = (String) request.getAttribute("org.cloudfoundry.router.xfcc.app.guid");
String spaceGuid = (String) request.getAttribute("org.cloudfoundry.router.xfcc.space.guid");
String orgGuid   = (String) request.getAttribute("org.cloudfoundry.router.xfcc.org.guid");
```

### Request attributes

Set when the header is in XFCC format (first entry containing the field wins for multi-entry headers). Any attribute may be `null` -- always null-check, since the header may be absent or carry only some fields.

| Attribute | Source | Value |
|-----------|--------|-------|
| `org.cloudfoundry.router.xfcc.hash` | `Hash=` | SHA-256 fingerprint of the client certificate |
| `org.cloudfoundry.router.xfcc.subject` | `Subject=` | Full Subject DN of the client certificate |
| `org.cloudfoundry.router.xfcc.app.guid` | `Subject=` `OU=app:<guid>` | CF app GUID |
| `org.cloudfoundry.router.xfcc.space.guid` | `Subject=` `OU=space:<guid>` | CF space GUID |
| `org.cloudfoundry.router.xfcc.org.guid` | `Subject=` `OU=organization:<guid>` | CF organization GUID |
| `org.cloudfoundry.router.xfcc.instance.guid` | `Subject=` `CN=<guid>` | CF app instance GUID |

Header parsing details -- format detection, fallback behaviour, Gorouter `xfcc_format` specifics -- are in [docs/XFCC.md](docs/XFCC.md).

## Configuration

### Certificate caching

On by default. Parsed results are reused across requests carrying the same `X-Forwarded-Client-Cert` value, which skips the base64/PEM decode, the ASN.1 parse and the Subject DN parse, and reuses the `X509Certificate` object. Measured savings per call, worst-case hardware, working set inside the cache: 54.0 us to 2.1 us for an Envoy `Cert=` header, 3.6 us to 1.6 us for a Gorouter raw base64 certificate, 1.5 us to 0.3 us for a CF app-identity header. Full matrix in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

Entries are keyed by the header value itself, so only a byte-for-byte identical header hits and `equals()` confirms every hit -- no derived key can map two different headers onto one certificate.

**Turn it off** (`org.cloudfoundry.router.certificate.cache.enabled=false`) when more distinct client certificates are in rotation than the cache holds, since a cache that mostly misses is pure overhead, or when the memory does not suit your deployment. `org.cloudfoundry.router.certificate.cache.size` sets the entries per generation (two generations, so `2 x size` entries); invalid or non-positive values are ignored and the default is used, with a warning logged. Each entry retains the header string plus the parsed certificate, so the rough bound is `2 x size x (header bytes + parsed certificate)` -- about 1 MB at the default for CF-sized headers, proportionally more where `maxHttpHeaderSize` has been raised for large certificates. The filter logs its effective cache configuration at `INFO` on startup and warns when the hit rate is low.

Cached certificates are **not** expiry-checked on retrieval; see [docs/TRUST-BOUNDARY.md](docs/TRUST-BOUNDARY.md).

### Header hiding

With `org.cloudfoundry.router.certificate.header.hide=true`, the `X-Forwarded-Client-Cert` header is hidden from downstream filters and servlets once parsed, via an `HttpServletRequestWrapper`. This keeps large base64 certificate values out of request logging filters (`CommonsRequestLoggingFilter`, Tomcat `RequestDumperValve`), security filters that iterate all headers, and Servlet-`Filter`-based tracing instrumentation placed after this filter.

Opt-in, because it changes downstream *behaviour*, not just performance: any code after this filter that gates logic on the presence of the raw header would silently stop seeing it -- a fail-open risk. Enable it once you've confirmed no downstream code depends on the raw header.

Caveats:

- Only affects code reading the header via the wrapped `HttpServletRequest` *after* this filter. Bytecode-instrumented tracing agents (e.g. the OpenTelemetry Java agent) capture headers at the container / dispatch level, before the wrapper takes effect.
- The header is hidden whenever present, even when parsing failed -- downstream code must not read "no header" as "no client certificate was presented".
- **Async:** the wrapper preserves itself across `startAsync()`, but if a downstream filter wraps the response again before calling the no-arg `startAsync()`, that newer response wrapper is not visible here and a stale response is passed to `startAsync(request, response)` -- a known limitation.

## Error handling

Certificate parse failures (invalid Base64, invalid `CertificateFactory` input, malformed URL-encoded values such as a `%GG` sequence) are caught inside `doFilter()`, logged as a `WARNING`, and the request continues down the filter chain without the certificate attribute set.

## Debug logging

The filter uses Java Util Logging (JUL). Set the logger level for `org.cloudfoundry.router` to `FINE` to log the recognised XFCC field names present in each header (e.g. `Hash`, `Cert`, `Subject`). Certificate values are never logged.

## More documentation

- [docs/TRUST-BOUNDARY.md](docs/TRUST-BOUNDARY.md) -- what the filter does and does not guarantee, and what your app should check
- [docs/XFCC.md](docs/XFCC.md) -- header formats, detection rules, CF Gorouter specifics
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) -- cache design, benchmarks, memory
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) -- building from source, CI workflows

## License

This project is released under version 2.0 of the [Apache License][l].

[l]: https://www.apache.org/licenses/LICENSE-2.0
[xfcc]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
