# nuqs repro — issues #1069 / #1114

> nginx servers return errors when special characters `{}|\^` are present in query parameters
> https://github.com/47ng/nuqs/issues/1069

> AWS API Gateway returns 400 when `{}` are present in query values
> https://github.com/47ng/nuqs/issues/1114

Test rig probing which servers/proxies reject query strings containing the
characters nuqs leaves unencoded (`{ } | \ ^ [ ] ?` …).

## Setup

- nginx 1.18, 1.20, 1.24, 1.28, latest — HTTP/1.1 and h2c, static response
  and `proxy_pass`
- nginx + ModSecurity v3 + OWASP Core Rule Set (CRS 4.28), blocking paranoia
  levels 1 through 4
- Tomcat 9 & 10.1, Jetty 12, Apache httpd 2.4, HAProxy 3.0, Caddy 2,
  Envoy 1.32, OpenLiteSpeed
- Payloads sent raw with `curl -g` (globoff, so `{}` and `[]` reach the wire
  unescaped); raw wire bytes verified in nginx access logs (`$request`)

## Run

```sh
docker compose up -d
# wait for modsecurity containers to become healthy
./test.sh
```

## Results (2026-07-03)

| Target                       | raw `{ } \| \ ^` | raw `[ ]` | percent-encoded |
| ---------------------------- | ---------------- | --------- | --------------- |
| nginx 1.18 → latest (all)    | pass             | pass      | pass            |
| Jetty 12, httpd 2.4          | pass             | pass      | pass            |
| HAProxy 3.0, Caddy 2         | pass             | pass      | pass            |
| Envoy 1.32, OpenLiteSpeed    | pass             | pass      | pass            |
| **Tomcat 9 / 10.1**          | **400**          | **400**   | pass            |
| ModSecurity CRS PL1          | pass             | pass      | pass            |
| ModSecurity CRS PL2–3 ¹      | partial          | partial   | **403** ¹       |
| ModSecurity CRS PL4          | **403**          | **403**   | **403**         |

¹ PL2–3 pass single characters but 403 realistic nuqs payloads:
`{"foo":"bar"}` (parseAsJson output) and `a|b,c|d` trip SQL-injection
heuristics (CRS rules 942200, 942340, 942430) — raw **and**
percent-encoded, since ModSecurity url-decodes before matching.

### nginx (issue #1069 claim)

Cannot reproduce with any vanilla nginx: every version, over HTTP/1.1 and
HTTP/2, static and proxied, accepts all of `{ } | \ ^ ? [ ]` raw in query
values. nginx only rejects spaces and control characters in the request
line (tightened in 1.21.1 — still not these characters). The "some nginx
servers" in #1069 most likely had a WAF (ModSecurity/naxsi/hosting-panel
rules) or custom `if ($args ~ …)` config in front.

### Tomcat — the reproducible case for the #1069/#1114 symptom class

Tomcat 9 and 10.1 reject **every** request with raw `{ } | \ ^ [ ]` in the
query string, before any servlet runs:

```
400 — Invalid character found in the request target [/?q={ ].
      The valid characters are defined in RFC 7230 and RFC 3986
```

Percent-encoded equivalents pass. This matches the reported AWS API Gateway
behaviour in #1114 (400, no logs — rejected at the front door), except API
Gateway reportedly tolerates `[ ]`.

Tomcat's `relaxedQueryChars` connector attribute can re-allow specific
characters server-side.

### ModSecurity / WAF class — not fixable by client-side encoding

- CRS rule 920273 (PL4) "Invalid character in request (outside of very
  strict set)": `ValidateByteRange 38,44-46,48-58,61,65-90,95,97-122`
  applied **after** `t:urlDecodeUni` — only `& , - . / 0-9 : = A-Z _ a-z`
  survive, encoded or not. Also blocks `! ( ) * ~ '` — characters
  `encodeURIComponent` leaves raw. No client-side encoding satisfies PL4.
- CRS PL2–3 SQLi heuristics fire on JSON-ish and pipe-delimited *content*,
  raw or encoded.

### Browsers agree with nuqs

Chrome sends `{ } | \ ^ [ ]` raw on the wire in query strings (verified via
nginx access log; only `"` `<` `>` and controls are encoded, per the
[URL Standard query percent-encode set](https://url.spec.whatwg.org/#query-percent-encode-set)).
A hand-typed URL hits the same server behaviour as a nuqs-generated one.

## Character-set analysis

RFC 3986 `query = *( pchar / "/" / "?" )`, with
`pchar = unreserved / pct-encoded / sub-delims / ":" / "@"`.

Of the characters nuqs currently leaves unencoded
(`-._~!$()*,;=:@/?[]{}\|^`):

- **RFC-valid:** `- . _ ~ ! $ ( ) * , ; = : @ / ?` — safe for any
  spec-compliant server (Tomcat, API Gateway accept them).
- **RFC-invalid:** `[ ] { } \ | ^` — exactly the 7 characters that strict
  servers reject.

PR #1068 encodes `{ } | \ ^ ?` — it needlessly encodes `?` (RFC-valid,
accepted everywhere tested) and misses `[ ]` (Tomcat rejects them).
Encoding the 7 RFC-invalid characters would achieve full RFC 3986
compliance while keeping the "pretty" RFC-valid set raw — fixing the
Tomcat/API-Gateway class. The WAF class (ModSecurity CRS PL2+) is
content-based and cannot be fixed by any encoding.
