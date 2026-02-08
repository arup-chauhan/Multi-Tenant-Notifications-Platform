wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"

request = function()
  local body = '{"tenant_id":"tenant-a","user_id":"u1","channel":"alerts","content":"wrk-notification"}'
  return wrk.format(wrk.method, "/v1/notifications", wrk.headers, body)
end
