# nuqs repro attempt — issue #1069

> nginx servers return errors when special characters `{}|\^` are present in query parameters
> https://github.com/47ng/nuqs/issues/1069

Test rig probing whether nginx rejects query strings containing the
characters nuqs leaves unencoded (`{ } | \ ^ ?`).

## Setup

- nginx 1.18, 1.20, 1.24, 1.28, latest — HTTP/1.1 and h2c, static response
  and `proxy_pass`
- nginx + ModSecurity v3 + OWASP Core Rule Set (CRS 4.28), blocking paranoia
  levels 1 through 4
- Payloads sent raw with `curl -g` (globoff, so `{}` and `[]` reach the wire
  unescaped); raw wire bytes verified in nginx access logs (`$request`)

## Run

```sh
docker compose up -d
# wait for modsecurity containers to become healthy
./test.sh
```

## Results (2026-07-03)

| Target                        | `{ } \| \ ^ ?` raw | percent-encoded |
| ----------------------------- | ------------------ | --------------- |
| nginx 1.18 → latest (all)     | 200                | 200             |
| ModSecurity CRS paranoia 1–3  | 200                | 200             |
| ModSecurity CRS paranoia 4    | **403**            | **403**         |

1. **Vanilla nginx cannot be the reported failure.** Every version tested,
   over HTTP/1.1 and HTTP/2, static and proxied, accepts all of
   `{ } | \ ^ ?` raw in query values. nginx only rejects spaces and control
   characters in the request line (tightened in 1.21.1 — still not these
   characters).

2. **The only reproducible 403 is OWASP CRS at paranoia level 4**, rule
   [920273](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf)
   "Invalid character in request (outside of very strict set)":
   `ValidateByteRange 38,44-46,48-58,61,65-90,95,97-122` — i.e. only
   `& , - . / 0-9 : = A-Z _ a-z` are allowed in arg values.

3. **Percent-encoding does not help against that rule.** 920273 applies
   `t:urlDecodeUni` before validating, so `%7B` is decoded back to `{` and
   still scores. `a%2Ab` (an encoded `*`) is also blocked. The encoding
   change proposed in PR #1068 would not fix the PL4 case.

4. **PL4 also blocks characters that `encodeURIComponent` leaves raw:**
   `! ( ) * ~ '` all return 403. Even an app that fully encodes with
   `encodeURIComponent` (or `URLSearchParams`, which leaves `*` raw) breaks
   at PL4. This is a server-side allowlist that no client-side encoding can
   satisfy; PL4 deployments are expected to whitelist app-specific false
   positives.

5. **Browsers agree with nuqs.** Chrome sends `{ } | \ ^` raw on the wire in
   query strings (verified via nginx access log; only `"` `<` `>` and
   controls are encoded, per the [URL Standard query percent-encode
   set](https://url.spec.whatwg.org/#query-percent-encode-set)). A
   hand-typed URL in the address bar hits the same server behaviour as a
   nuqs-generated one.

## Conclusion

Cannot reproduce with any vanilla nginx. The only nginx setup found that
rejects these characters (OWASP CRS PL4) rejects them **whether or not they
are percent-encoded**, and also rejects characters that every standard URL
encoder leaves raw — so the fix proposed in PR #1068 would not resolve it.
The failure reported in #1069 most likely comes from a WAF/custom rule in
front of nginx, and needs the reporter's actual config to investigate
further.
