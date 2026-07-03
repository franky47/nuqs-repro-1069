#!/usr/bin/env bash
# Fires query strings containing the characters from nuqs issues #1069/#1114
# ({ } | \ ^ ?) at various servers/proxies, and reports HTTP status codes.
# curl -g (globoff) is required so {} and [] reach the wire unescaped.
# A status differing from the target's own 'plain' baseline is flagged.
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

# name|base_url|paths(comma-separated)|curl_http_option
declare -a TARGETS=(
  'nginx-1.18-http1|http://localhost:8118|static,proxy|--http1.1'
  'nginx-1.20-http1|http://localhost:8120|static,proxy|--http1.1'
  'nginx-1.24-http1|http://localhost:8124|static,proxy|--http1.1'
  'nginx-1.28-http1|http://localhost:8128|static,proxy|--http1.1'
  'nginx-latest-http1|http://localhost:8199|static,proxy|--http1.1'
  'nginx-1.18-h2c|http://localhost:9118|static,proxy|--http2-prior-knowledge'
  'nginx-1.20-h2c|http://localhost:9120|static,proxy|--http2-prior-knowledge'
  'nginx-1.24-h2c|http://localhost:9124|static,proxy|--http2-prior-knowledge'
  'nginx-1.28-h2c|http://localhost:9128|static,proxy|--http2-prior-knowledge'
  'nginx-latest-h2c|http://localhost:9199|static,proxy|--http2-prior-knowledge'
  'modsecurity-pl1|http://localhost:8181|static,proxy|--http1.1'
  'modsecurity-pl2|http://localhost:8182|static,proxy|--http1.1'
  'modsecurity-pl3|http://localhost:8183|static,proxy|--http1.1'
  'modsecurity-pl4|http://localhost:8184|static,proxy|--http1.1'
  'tomcat-9|http://localhost:8209||--http1.1'
  'tomcat-10|http://localhost:8210||--http1.1'
  'jetty-12|http://localhost:8211||--http1.1'
  'httpd-2.4|http://localhost:8212||--http1.1'
  'haproxy-3.0|http://localhost:8213|static,proxy|--http1.1'
  'caddy-2|http://localhost:8214||--http1.1'
  'envoy-1.32|http://localhost:8215|static,proxy|--http1.1'
  'openlitespeed|http://localhost:8216||--http1.1'
)

printf '%-22s %-10s %-28s %s\n' TARGET PATH PAYLOAD STATUS

for target in "${TARGETS[@]}"; do
  IFS='|' read -r name base paths http_opt <<<"$target"
  IFS=',' read -ra path_list <<<"${paths:-.}"
  for path in "${path_list[@]}"; do
    [[ "$path" == '.' ]] && path=''
    baseline=''
    for payload in "${PAYLOADS[@]}"; do
      status=$(curl -g -s -o /dev/null -w '%{http_code}' $http_opt \
        --connect-timeout 3 --max-time 5 \
        "$base/$path?q=$payload")
      [[ -z "$baseline" ]] && baseline="$status"
      marker=''
      [[ "$status" != "$baseline" ]] && marker='  <-- !'
      printf '%-22s %-10s %-28s %s%s\n' "$name" "${path:-/}" "$payload" "$status" "$marker"
    done
  done
done
