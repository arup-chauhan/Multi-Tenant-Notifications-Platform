#!/usr/bin/env bash

base64url_encode() {
  printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

build_hs256_jwt() {
  local tenant_id="$1"
  local user_id="$2"
  local iat="$3"
  local nbf="$4"
  local exp="$5"
  local secret="$6"
  local header payload header_b64 payload_b64 signing_input signature
  header='{"alg":"HS256","typ":"JWT"}'
  payload="{\"tenant_id\":\"$tenant_id\",\"sub\":\"$user_id\",\"iat\":$iat,\"nbf\":$nbf,\"exp\":$exp}"
  header_b64="$(base64url_encode "$header")"
  payload_b64="$(base64url_encode "$payload")"
  signing_input="${header_b64}.${payload_b64}"
  signature="$(printf '%s' "$signing_input" | openssl dgst -binary -sha256 -hmac "$secret" | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  printf '%s.%s' "$signing_input" "$signature"
}
