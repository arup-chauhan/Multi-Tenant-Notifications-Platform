wrk.method = "GET"

request = function()
  return wrk.format(wrk.method, "/health")
end
