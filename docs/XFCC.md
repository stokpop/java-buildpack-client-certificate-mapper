# XFCC header handling

Details of how `X-Forwarded-Client-Cert` is detected and parsed. For the request attributes the filter sets, see the [README](../README.md#request-attributes).

## Supported forms

- Base64-encoded DER certificate (raw header value)
- URL-encoded PEM certificate (raw header value)
- [Envoy XFCC format][xfcc] -- key-value fields such as `Hash=`, `Cert=`, `Subject=`, `Chain=`

Field names are matched case-insensitively. Multiple header values and the [RFC 9110 section 5.3][rfc9110] comma-delimited equivalent are both supported. JSON format is not supported.

The `Hash=` field (a SHA-256 fingerprint of the leaf certificate, set by the router) is recognised for format detection, and when present is checked for the shape of a SHA-256 hex digest -- a value that does not match is logged as a warning, not rejected. `Hash=` alone cannot be mapped to an `X509Certificate`; that needs a `Cert=` field.

## Detection and fallback

An entry is detected as XFCC format when it structurally begins with a short (<= 20 characters) all-letter key followed by `=`, **and** contains at least one of `Hash=`, `Cert=`, `Chain=`, or `Subject=`.

If an entry passes the structural check but contains none of those recognised fields (e.g. only unknown future fields), it is treated as a raw certificate value; parsing will fail and a warning is logged. This preserves the same external behaviour as the raw-cert fallback path.

Unknown fields are skipped, with their position (not their name) logged at `FINE` level.

## CF Gorouter XFCC fields

CF Gorouter's XFCC output depends on the per-domain `xfcc_format` setting:

- **`xfcc_format: envoy`** (used on mTLS domains such as CF app-identity) emits the compact field form `Hash=<sha256-hex>;Subject="<DN>"` -- **only** `Hash=` and `Subject=`. Gorouter never emits a `Cert=` field in this mode.
- **`xfcc_format: raw`** (the non-mTLS default) emits the **whole leaf certificate** as the base64 header value, with no `Hash=`/`Subject=`/`Cert=` field prefix.

So the `Cert=` field this library parses comes from a real Envoy proxy (or another XFCC producer), not from Gorouter -- Gorouter conveys the full certificate via the raw format instead. `By=`, `URI=`, and `DNS=` are not emitted for CF app-identity certs (they carry no URI/DNS SANs) and are not recognised by this library.

## CF Subject DN format

```
CN=<instance-guid>,OU=app:<app-guid>,OU=space:<space-guid>,OU=organization:<org-guid>
```

The CF identity attributes are parsed from this DN and are set regardless of whether a `Cert=` field is present, so applications can identify the caller even when only `Hash=` and `Subject=` are forwarded.

## Specifications

- [Envoy `x-forwarded-client-cert` header][xfcc] -- XFCC field definitions (`Hash=`, `Cert=`, `Chain=`, `Subject=`)
- [RFC 9110 section 5.3][rfc9110] -- HTTP header comma-delimited field values
- [Jakarta Servlet 6.0 specification][servlet-spec] -- `jakarta.servlet.request.X509Certificate` attribute

[xfcc]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110#section-5.3
[servlet-spec]: https://jakarta.ee/specifications/servlet/6.0/
