# XFCC header handling

How `X-Forwarded-Client-Cert` is detected and parsed. For the attributes the filter sets, see the [README](../README.md#request-attributes).

## Supported forms

- Base64-encoded DER certificate (raw header value)
- PEM certificate, normally URL-encoded (raw header value, or an Envoy `Cert=` field)
- [Envoy XFCC format][xfcc] -- key-value fields such as `Hash=`, `Cert=`, `Subject=`, `Chain=`

DER is the certificate's binary ASN.1 encoding. PEM is that same DER base64-encoded and wrapped in `-----BEGIN/END CERTIFICATE-----` lines -- the *armor* -- so it survives text channels such as an HTTP header.

Field names match case-insensitively. Multiple header values and the [RFC 9110 section 5.3][rfc9110] comma-delimited equivalent are both supported. JSON format is not.

`Hash=` (a SHA-256 fingerprint of the leaf certificate, set by the router) is recognised for format detection and checked for the shape of a SHA-256 hex digest -- a mismatch is warned, not rejected. `Hash=` alone cannot map to an `X509Certificate`; that needs `Cert=`.

Envoy quotes its `Cert=`, `Chain=` and `Subject=` values (`absl::StrCat("Cert=\"", ...)`); surrounding quotes are stripped and RFC 9110 quoted-pairs unescaped before decoding.

## Encoding, as the producers emit it

| Producer | Emits |
| --- | --- |
| Envoy `Cert=` | URL-encoded PEM, quoted; percent-encoding leaves the RFC 3986 unreserved set (including `-`) literal |
| nginx `$ssl_client_escaped_cert` | URL-encoded PEM; `ngx_escape_uri` likewise leaves `-` literal, escapes space as `%20` |
| CF Gorouter `xfcc_format: raw` | base64 DER: PEM with `-----BEGIN/END CERTIFICATE-----` and newlines removed |
| CF Gorouter `xfcc_format: envoy` | `Hash=<sha256-hex>;Subject="<DN>"` -- never `Cert=` |

The filter detects the format rather than trying decoders in turn: a `%` means URL-encoded, PEM armor means PEM (decoded to DER before parsing, which is much cheaper -- see [PERFORMANCE.md](PERFORMANCE.md)), anything else is base64 DER. Routers that escape more than they must (percent-encoding the armor dashes as `%2D`) decode the same way.

## Detection and fallback

An entry is XFCC format when it structurally begins with a short (<= 20 characters) all-letter key followed by `=`, **and** contains at least one of `Hash=`, `Cert=`, `Chain=`, `Subject=`.

An entry that passes the structural check but carries none of those fields (e.g. only unknown future fields) is treated as a raw certificate value; parsing then fails with a warning, preserving the raw-cert fallback behaviour. Unknown fields are skipped, with their position (not their name) logged at `FINE`.

## CF Gorouter specifics

`xfcc_format` is set per domain (`routing-release`, `config.XFCC_FORMAT_RAW` / `XFCC_FORMAT_ENVOY`):

- **`envoy`** (mTLS domains, CF app-identity) emits `Hash=` and `Subject=` only. Gorouter never emits `Cert=` in this mode.
- **`raw`** (the non-mTLS default) emits the whole leaf certificate as the base64 header value, with no field prefix.

So a `Cert=` field comes from a real Envoy proxy or another XFCC producer, not from Gorouter. `By=`, `URI=` and `DNS=` are not emitted for CF app-identity certificates and are not recognised here.

## CF Subject DN format

```
CN=<instance-guid>,OU=app:<app-guid>,OU=space:<space-guid>,OU=organization:<org-guid>
```

The CF identity attributes are parsed from this DN whether or not a `Cert=` field is present, so applications can identify the caller when only `Hash=` and `Subject=` are forwarded.

## Specifications

- [Envoy `x-forwarded-client-cert` header][xfcc] -- XFCC field definitions
- [RFC 9110 section 5.3][rfc9110] -- comma-delimited header field values
- [Jakarta Servlet 6.0][servlet-spec] -- `jakarta.servlet.request.X509Certificate`

[xfcc]: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
[rfc9110]: https://www.rfc-editor.org/rfc/rfc9110#section-5.3
[servlet-spec]: https://jakarta.ee/specifications/servlet/6.0/
