# Trust boundary and certificate validity

This filter maps `X-Forwarded-Client-Cert` **verbatim**. It does **not** verify certificate trust, validity, or that the caller proved possession of the private key. Those guarantees come entirely from the fronting proxy that terminated the (mutual) TLS connection and set the header -- CF Gorouter is one example, but the same applies to any router or gateway.

The mapped attributes are therefore trustworthy **only** if requests reach your app exclusively via that proxy, and the proxy strips any client-supplied copy of the header (CF Gorouter `forwarded_client_cert: sanitize_set`, Envoy's default `SANITIZE`/`SANITIZE_SET`; the pass-through modes `always_forward` and `ALWAYS_FORWARD_ONLY` forward whatever the client sent). If your instance is reachable directly, the header is attacker-controllable and no app-side check can recover the missing possession proof: a forwarded certificate proves the proxy *saw* it, not that the caller *holds* it.

## What your app can check

- **Identity-only header (`Hash=` + `Subject=`, e.g. CF app-identity on an mTLS domain).** No `X509Certificate` is mapped, so `checkValidity()` is not possible -- there are no certificate bytes. The proxy already validated chain and validity during the handshake, and CF instance-identity certificates are short-lived. Treat the `xfcc.*` attributes as a post-validation identity assertion.
- **Full-certificate header (`Cert=`, or a raw certificate value).** An `X509Certificate` is mapped, so your app can and should enforce its own checks as defence in depth -- `cert.checkValidity()`, chain verification against a trusted CA. This filter does none of that.

## Caching and validity

Cached entries are not expiry-checked on retrieval, on hits or misses -- the same behaviour as before caching existed. Applications requiring expiry enforcement should call `X509Certificate.checkValidity()` on the mapped attribute.

## Cache identity

The cache is keyed by the XFCC entry exactly as received, and `String.equals()` confirms every hit, so two different header values cannot resolve to one cached certificate. Earlier revisions keyed on a SHA-256 digest, making collisions a (cryptographically infeasible) correctness question; keying on the value removes the question rather than arguing it away.

Enable the cache only behind a router that sanitizes `X-Forwarded-Client-Cert`. A client that controls the header can choose values with colliding Java hash codes, and misses on colliding values are parsed one at a time under a map lock rather than in parallel.

## Header hiding is fail-open for downstream checks

With `org.cloudfoundry.router.certificate.header.hide=true`, the header is hidden whenever present, *regardless* of whether a certificate was parsed from it. Downstream code must not read "raw header absent" as "no client certificate was presented": a malformed or attacker-supplied value produces the same downstream signal as a request that never carried the header. Downstream authorization should key off the request attributes this filter sets, not raw header presence.
