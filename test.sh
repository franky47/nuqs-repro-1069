#!/usr/bin/env bash
# Fires query strings containing the characters from nuqs issue #1069
# ({ } | \ ^ ?) at various nginx setups, and reports HTTP status codes.
# curl -g (globoff) is required so {} and [] reach the wire unescaped.
set -u

declare -a PAYLOADS=(
  'plain'
  '{'
  '}'
  '|'
  '\'
  '^'
  '?'
  '{}|\^?'
  '{"foo":"bar"}'
  'a|b,c|d'
  '-._~!$()*,;=:@/?[]{}\|^'
)

declare -a TARGETS=(
  'nginx-1.18-http1|http://localhost:8118'
  'nginx-1.20-http1|http://localhost:8120'
  'nginx-1.24-http1|http://localhost:8124'
  'nginx-1.28-http1|http://localhost:8128'
  'nginx-latest-http1|http://localhost:8199'
  'nginx-1.18-h2c|http://localhost:9118'
  'nginx-1.20-h2c|http://localhost:9120'
  'nginx-1.24-h2c|http://localhost:9124'
  'nginx-1.28-h2c|http://localhost:9128'
  'nginx-latest-h2c|http://localhost:9199'
  'modsecurity-pl1|http://localhost:8181'
  'modsecurity-pl4|http://localhost:8184'
)

printf '%-22s %-10s %-28s %s\n' TARGET PATH PAYLOAD STATUS

for target in "${TARGETS[@]}"; do
  name="${target%%|*}"
  base="${target#*|}"
  http_opt='--http1.1'
  [[ "$name" == *-h2c ]] && http_opt='--http2-prior-knowledge'
  for path in static proxy; do
    for payload in "${PAYLOADS[@]}"; do
      status=$(curl -g -s -o /dev/null -w '%{http_code}' $http_opt \
        --connect-timeout 3 --max-time 5 \
        "$base/$path?q=$payload")
      marker=''
      [[ "$status" != 200 ]] && marker='  <-- !'
      printf '%-22s %-10s %-28s %s%s\n' "$name" "$path" "$payload" "$status" "$marker"
    done
  done
done
