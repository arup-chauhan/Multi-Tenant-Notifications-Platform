wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"

local token = os.getenv("WRK_BEARER_TOKEN") or ""
if token ~= "" then
  wrk.headers["Authorization"] = "Bearer " .. token
end

request = function()
  local body = '{"tenant_id":"tenant-a","user_id":"u1","channel":"alerts","content":"wrk-auth-notification"}'
  return wrk.format(wrk.method, "/v1/notifications", wrk.headers, body)
end
