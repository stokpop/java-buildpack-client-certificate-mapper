# Error handling

A malformed `X-Forwarded-Client-Cert` never fails the request. The filter logs a warning and passes the request on without a client identity; your application decides what an anonymous request gets, for example a 401 or 403.

## Nothing is published

`doFilter()` catches `CertificateException`, `IOException` and `IllegalArgumentException`, logs `Unable to parse certificates in X-Forwarded-Client-Cert` as a `WARNING`, and sets **no** `X509Certificate` attribute and **no** XFCC attributes (`Hash`, `Subject`, CF GUIDs) for the request. This covers:

- a `Cert=` or raw header value that is not a certificate, or is truncated
- a PEM body that is not valid base64 -- rejected strictly, not recovered by skipping illegal characters
- a malformed URL escape such as `%GG`
- **any one** bad entry in a multi-entry header: the valid entries are dropped too

The last point is deliberate. Every entry is resolved before anything is published, because a router that terminated the TLS connection writes a valid certificate: a corrupt entry means the header is not what the router produced, so the rest of it is not trusted either. Publishing the valid entries' identity would leave a partial state -- CF GUIDs without a certificate -- that the application cannot tell apart from a genuine identity-only header.

Header hiding (`org.cloudfoundry.router.certificate.header.hide`) still applies when parsing failed; see [TRUST-BOUNDARY.md](TRUST-BOUNDARY.md).

### Telling a failed header from no header

No attribute marks a failure, so an endpoint that serves both anonymous and mTLS callers sees a failed header as an anonymous call. Security-wise that is sound -- a caller can always look anonymous by presenting no certificate -- but a legitimate client whose header was mangled on the way gets the anonymous response instead of an error.

With header hiding **off** (the default) the header is still visible, so the application can detect the failure itself: the header is present, yet neither the certificate nor any XFCC attribute was set.

```java
String header = request.getHeader("X-Forwarded-Client-Cert");
boolean headerSent = header != null && !header.trim().isEmpty();
boolean identityMapped =
    // a certificate: raw header value, or XFCC with Cert=
    request.getAttribute("jakarta.servlet.request.X509Certificate") != null
    // no certificate, but identity: e.g. CF app identity, which sends only Hash= and Subject=
    || request.getAttribute("org.cloudfoundry.router.xfcc.hash") != null
    || request.getAttribute("org.cloudfoundry.router.xfcc.subject") != null;
if (headerSent && !identityMapped) {
    // The header could not be parsed: answer 400 rather than treating the caller as anonymous.
}
```

Use the `javax.` attribute name on older containers. With header hiding **on** the header is hidden even when parsing failed, so this check is not possible.

## Warned, but still published

- **`Hash=` that is not a 64-character hex SHA-256** -- a shape check only; the value is published as sent.
- **`Chain=` without `Cert=`** -- `Chain=` is not supported, so no certificate is mapped; `Hash=` and `Subject=` identity is still published.

## Failing the request or the application

- **Per request:** no header content is known to escape the filter. What remains is theoretical: a JCA provider throwing a `RuntimeException` instead of a `CertificateException` (neither `SUN` nor BouncyCastle does), or a JVM `Error`. Exceptions thrown further down the chain are the application's own.
- **At startup:** an unregistered or unusable `org.cloudfoundry.router.certificate.provider` logs a warning and falls back to the platform default. Only a JVM with no X.509 `CertificateFactory` at all -- not a normal JDK -- stops the filter from being created, and with it the application from starting.

## Compared with 2.0.x

2.0.x handled a corrupt value the same way -- warning, no certificate, request continues -- and dropped every certificate when one entry of several failed. It had no XFCC identity attributes. The difference: a malformed URL escape such as `%GG` threw an `IllegalArgumentException` that 2.0.x did not catch, so it escaped the filter and failed the request, typically with a 500.
