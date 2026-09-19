# Trust boundary and certificate validity

This filter maps the incoming `X-Forwarded-Client-Cert` header **verbatim**. It does **not** verify certificate trust, validity, or that the caller proved possession of the private key. Those guarantees come entirely from whichever fronting proxy terminated the (mutual) TLS connection and set the header -- CF Gorouter is one example, but the same applies to any router or gateway, inside or outside CF.

The mapped attributes are therefore trustworthy **only** if requests reach your app exclusively via that trusted proxy, and any client-supplied copy of the header on untrusted inbound paths is stripped by it. Whether the proxy strips and replaces the header is a proxy configuration choice (e.g. CF Gorouter `forwarded_client_cert: sanitize_set`, or Envoy's default `SANITIZE`/`SANITIZE_SET`); pass-through modes (Gorouter `always_forward`, Envoy `ALWAYS_FORWARD_ONLY`) forward whatever the client sent. If your instance is reachable directly, bypassing the proxy, the header is attacker-controllable and no app-side check can recover the missing possession proof -- a forwarded certificate proves only that the proxy *saw* it, not that the caller *holds* it.

## What your app can check

- **Identity-only header (`Hash=` + `Subject=`, e.g. CF app-identity on an mTLS domain).** No `X509Certificate` is mapped, so your app **cannot** call `checkValidity()` -- there are no certificate bytes. It does not need to: the proxy already required and validated the client certificate during the mTLS handshake (chain and validity period) before emitting the header, and CF instance-identity certificates are short-lived. Treat the `xfcc.*` attributes as a post-validation identity assertion, trusted transitively via the proxy.
- **Full-certificate header (`Cert=`, or a raw certificate value).** An `X509Certificate` is mapped, so your app **can and should** enforce its own checks where appropriate -- e.g. `cert.checkValidity()` and verifying the chain against a trusted CA -- as defence in depth. This filter does none of that.

## Caching and validity

Cached entries are not expiry-checked on retrieval. The filter does not validate certificate validity on cache hits (nor on misses) -- consistent with behaviour before caching was introduced. Applications that require expiry enforcement should check `X509Certificate.checkValidity()` on the mapped request attribute.

## Cache identity

The cache is keyed by the `X-Forwarded-Client-Cert` entry exactly as received, and `String.equals()` confirms every hit, so two different header values cannot resolve to one cached certificate. Earlier revisions keyed on a SHA-256 digest of the header, which made key collisions a (cryptographically infeasible) correctness question; keying on the value removes the question rather than arguing it away.

## Header hiding is fail-open for downstream checks

With `org.cloudfoundry.router.certificate.header.hide=true`, the header is hidden whenever it is present, *regardless* of whether this filter successfully parsed a certificate from it (a malformed or unparseable `Cert=`/raw value is logged as a warning, but the header is still hidden). Downstream code must not treat "raw header absent" as "no client certificate was ever presented" -- a malformed or attacker-supplied value produces the same downstream signal (no header, no `X509Certificate` attribute) as a request that never carried the header at all. Downstream authorization decisions should key off the request attributes this filter sets, not off raw header presence.
