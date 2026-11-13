# Process rules

Reuse `parse_message`. Do not use a real cache server. This lab decides whether a *response* may be stored under a *cache key* derived from the request, and what the stored artefact must look like.

`allow` means "safe to store under the reported key". `deny` means "must not store" (the request may still be forwarded, but that is out of scope).

## Cache key

The key is a canonical string, not a hash:

```
METHOD\n
normalized-target\n
host=<canonical host>\n
header:value\n   # for each keyed header, sorted by lowercase name
```

Details:

- METHOD is the request method, uppercased. If the request has `X-HTTP-Method-Override` or `X-Method-Override` (first match in that order) *and* `policy.ignore_method_override` is true (public: true), the override is *not* part of the method used for the key, but seeing an override on a cacheable GET/HEAD is `method_override` and you must deny store (attackers use it to poison a GET key with a POST body). If `ignore_method_override` is false, the override would change the key method; the public policy does not do that.
- `normalized-target` is the path + query of the request target (origin-form). If the target is absolute-form, take its path and query. Strip a trailing `/` only when the path is not `/`. Sort query parameters by name then value, decode once (`application/x-www-form-urlencoded` rules: `+` is space, `%HH` once). Drop query keys listed in `policy.unkeyed_query` (public: `utm_source`, `utm_medium`). A query key in `policy.forbidden_query` (public: `callback`, `_method`) is `dangerous_query` and deny.
- `host` is the `Host` header, lowercased, with a default port stripped (`:80` for http, `:443` for https if a scheme is known from an absolute-form target or `X-Forwarded-Proto`). If `Host` is missing, deny `missing_host`. If both `Host` and `X-Forwarded-Host` are present and they differ (after the same canonicalization) and `policy.keyed_headers` does not include `x-forwarded-host`, deny `unkeyed_host` — the Host in the key would not reflect the host the origin used to generate the body.
- `policy.keyed_headers` (lowercased) must be included in the key if present on the request. Values are stripped and compared case-sensitively, except `accept` and `accept-language` which are lowercased. If a header in `policy.must_key_if_present` (public: `x-forwarded-host`, `x-forwarded-proto`, `x-forwarded-scheme`, `origin`) is present and *not* in `keyed_headers`, deny `unkeyed_header` and name it in `notes`. Public `keyed_headers` is `["accept", "accept-language"]` only, so a request that also carries `X-Forwarded-Host` is denied.

## When not to store

In addition to the key rules above:

- Method not in `policy.cacheable_methods` (public: GET, HEAD) → `method_not_cacheable`. A GET with a non-empty body is `fat_get` (deny even if otherwise cacheable).
- Response status not in `policy.cacheable_status` (public: 200, 301, 404) → `status_not_cacheable`.
- Response has `Cache-Control` containing `no-store` or `private` (case-insensitive tokens) → `cache_control`.
- Response `Set-Cookie` is present and `policy.store_set_cookie` is false → `set_cookie`.
- Response header values or the body contain a CR or LF that is not part of the HTTP framing already stripped by the parser (i.e. inside a header value, or a raw CR/LF in the body when `policy.forbid_crlf_in_body` is true) → `response_splitting`.
- If `policy.enforce_type_by_ext` is true: a path ending with `.js` must have a JavaScript `Content-Type` (`application/javascript`, `text/javascript`, `application/x-javascript`); `.css` must be `text/css`. Otherwise `type_mismatch`. Types in `policy.unstoreable_types` (public includes `text/x-component`) are `type_mismatch` as well.
- If the request has `X-Forwarded-Proto: http` while the origin response has `Set-Cookie` with `Secure`, deny `proto_cookie` (and `set_cookie` when that also applies).

## Stored artefact

On allow, `stored` is an object `{key, status, headers, body_hex}` where headers are the response headers minus hop-by-hop names in `policy.hop_by_hop` (public: `connection`, `keep-alive`, `proxy-authenticate`, `transfer-encoding`, `upgrade`). On deny, `stored` is null and `key` should still be the computed key if you could compute it, else null.

## Report

`decision`, `reason_codes`, `key`, `stored`, `notes`.

Exit 0 on allow, 1 on deny, 2 if a message or policy cannot be read.

## Public fixtures

`--policy fixtures/policy.json --request fixtures/requests/NAME.raw --response fixtures/responses/NAME.raw` (same NAME):

- `ok-get` → allow
- `unkeyed-xfh` → deny `unkeyed_host` or `unkeyed_header`
- `method-override` → deny `method_override`
- `fat-get` → deny `fat_get`
- `set-cookie` → deny `set_cookie`
- `split-header` → deny `response_splitting`
- `dangerous-callback` → deny `dangerous_query`
- `ok-sorted-query` → allow, and the key must be identical to the key of `ok-get` after dropping `utm_source` (same path `/assets/app.js`)
