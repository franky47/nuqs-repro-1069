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
- nginx with the [7G Firewall](https://perishablepress.com/7g-firewall/)
  query-string rule (shipped as the built-in WAF of GridPane/xCloud managed
  WordPress hosting)
- nginx reverse-proxying Tomcat (`Server: nginx` from the client's view)
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

| Target                       | raw `{ }` | raw `\| \ ^` | raw `[ ]` | percent-encoded |
| ---------------------------- | --------- | ------------ | --------- | --------------- |
| nginx 1.18 → latest (all)    | pass      | pass         | pass      | pass            |
| Jetty 12, httpd 2.4          | pass      | pass         | pass      | pass            |
| HAProxy 3.0, Caddy 2         | pass      | pass         | pass      | pass            |
| Envoy 1.32, OpenLiteSpeed    | pass      | pass         | pass      | pass            |
| **Tomcat 9 / 10.1**          | **400**   | **400**      | **400**   | pass            |
| **nginx → Tomcat**           | **400**   | **400**      | **400**   | pass            |
| **nginx + 7G Firewall rule** | pass      | **403**      | pass      | pass            |
| ModSecurity CRS PL1          | pass      | pass         | pass      | pass            |
| ModSecurity CRS PL2–3 ¹      | partial   | partial      | partial   | **403** ¹       |
| ModSecurity CRS PL4          | **403**   | **403**      | **403**   | **403**         |

¹ PL2–3 pass single characters but 403 realistic nuqs payloads:
`{"foo":"bar"}` (parseAsJson output) and `a|b,c|d` trip SQL-injection
special-character-counting rules (CRS 942430 at PL2 threshold 12, 942431 at
PL3 threshold 6, plus 942200/942340) — raw **and** percent-encoded, since
ModSecurity url-decodes before matching.

## Issue #1069 — "some nginx servers" is true, and now reproducible

Vanilla nginx never rejects these characters: every version tested, over
HTTP/1.1 and HTTP/2, static and proxied, accepts all of `{ } | \ ^ ? [ ]`
raw in query values (nginx only rejects spaces and control characters in
the request line, tightened in 1.21.1). But three concrete nginx-branded
setups do reject them, all answering with `Server: nginx`:

1. **nginx reverse-proxying Tomcat** (in this rig: `nginx-tomcat`).
   Tomcat 400s the request; nginx hides the upstream `Server` header by
   default ([proxy module docs](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)),
   so the client sees nginx returning the error. Covers all of
   `{ } | \ ^ [ ]` — the only single mechanism matching the full set
   reported in #1069.
2. **nginx + 7G Firewall port** (in this rig: `nginx-7g`) — 403 on any
   query string containing raw `^`, `|` or `` ` `` / `\`. Shipped by
   GridPane and xCloud WordPress hosting, widely copy-pasted.
3. **nginx + naxsi** (not in this rig — needs a module build): core rules
   `id:1005` (`str:|`, score `$SQL:8`) and `id:1205` (`str:\`, score
   `$TRAVERSAL:4`) each block on a single occurrence under the canonical
   `CheckRule … BLOCK` setup
   ([naxsi_core.rules](https://raw.githubusercontent.com/wargio/naxsi/main/naxsi_rules/naxsi_core.rules)).

## Issue #1114 — AWS API Gateway: officially documented

The [API Gateway important notes](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html)
(REST APIs section) state:

> The plain text pipe character (|) and the curly brace character ({ or })
> are not supported for any request URL query string and must be
> URL-encoded.

Also: `;` in a query string "results in the data being split". `[ ]` are
tolerated (matches the reporter's observation). The rejection happens at
the front door — before the integration — which is why nothing shows in
CloudWatch ([community repro](https://forum.serverless.com/t/wsgi-app-errors-with-curly-brackets-in-query-strings-only-in-aws/16163):
Lambda never invoked, "400 from cloudfront" on edge-optimized endpoints).
The restriction is documented for REST APIs (v1) only; HTTP APIs (v2)
appear lenient (re-encode rather than reject — unconfirmed). No server-side
setting relaxes it.

Minimal live repro if ever needed: REST API + MOCK integration via AWS CLI
(no Lambda, ~zero cost), then
`curl -g 'https://<id>.execute-api.<region>.amazonaws.com/test?q={}'`.

## Tomcat details

Strict request-target validation since 8.5.7 / 8.0.39 / 7.0.73 (Nov 2016):

```
400 — Invalid character found in the request target [/?q={ ].
      The valid characters are defined in RFC 7230 and RFC 3986
```

Affects anything Tomcat-embedded: Spring Boot (default server), Confluence,
Jira, etc. The [`relaxedQueryChars`](https://tomcat.apache.org/tomcat-9.0-doc/config/http.html)
connector attribute can re-allow exactly `" < > [ \ ] ^ ` { | }`
server-side.

## What the specs say

- [RFC 3986 §3.4](https://www.rfc-editor.org/rfc/rfc3986#section-3.4):
  `query = *( pchar / "/" / "?" )` — `{ } | \ ^ [ ]` (and `" < >` backtick)
  are not producible raw; the only conforming form is percent-encoded.
- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112#section-3.2):
  recipients of an invalid request-line **SHOULD respond with 400** —
  Tomcat's documented rationale. Strict servers are the spec-compliant
  ones.
- [WHATWG URL Standard](https://url.spec.whatwg.org/#query-percent-encode-set):
  the query percent-encode set is only C0 controls, space, `"`, `#`, `<`,
  `>` — browsers serialize `{ } | \ ^ [ ]` raw in query strings (verified
  here via Chrome → nginx access log). Note the asymmetry: the *path*
  percent-encode set does include `{ } ^`, so browsers encode them in
  paths but not queries.

The WHATWG-vs-RFC-3986 split is deliberate (WHATWG codifies browser
behaviour and aims to obsolete RFC 3986; see Daniel Stenberg's
["My URL isn't your URL"](https://daniel.haxx.se/blog/2016/05/11/my-url-isnt-your-url/)).
nuqs currently sits on the WHATWG side; strict servers sit on the RFC side.

## Prior art

React Router (`createSearchParams`), TanStack Router
([qss.ts](https://github.com/TanStack/router/blob/main/packages/router-core/src/qss.ts))
and Next.js (`urlQueryToSearchParams`) all serialize through
`URLSearchParams.toString()`, which percent-encodes `{ } | \ ^ [ ]` (and
much more). Among mainstream routers, nuqs is the outlier in leaving them
raw (Vue Router is a partial exception).

## Character-set analysis

Of the characters nuqs currently leaves unencoded
(`-._~!$()*,;=:@/?[]{}\|^`):

- **RFC-valid:** `- . _ ~ ! $ ( ) * , ; = : @ / ?` — safe for any
  spec-compliant server (Tomcat and API Gateway accept them; `;` is safe
  in *values* but API Gateway splits on it).
- **RFC-invalid:** `[ ] { } \ | ^` — exactly the 7 characters that strict
  servers reject.

PR #1068 encodes `{ } | \ ^ ?` — it needlessly encodes `?` (RFC-valid,
accepted everywhere tested) and misses `[ ]` (Tomcat rejects them; API
Gateway happens to tolerate them).

**Encoding the 7 RFC-invalid characters** gives full RFC 3986 compliance
while keeping the "pretty" RFC-valid set raw. It fixes the strict-validator
class (Tomcat, nginx→Tomcat, API Gateway) and evades the 7G rule (which
matches the raw query string). It does **not** help against
content-inspecting WAFs (ModSecurity CRS PL2+ decodes before matching;
naxsi also decodes ARGS) — those need `configure({ renderQueryString })` /
server-side tuning regardless.
