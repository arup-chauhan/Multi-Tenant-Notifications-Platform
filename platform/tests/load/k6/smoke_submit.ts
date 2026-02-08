import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 1,
  iterations: 1,
};

const gatewayHttpBase = __ENV.GATEWAY_HTTP_BASE || "http://localhost:8080";
const tenantId = __ENV.K6_TENANT_ID || "tenant-demo";
const userId = __ENV.K6_USER_ID || "user-1";
const channel = __ENV.K6_CHANNEL || "alerts";
const content = __ENV.K6_CONTENT || "smoke notification";
const bearerToken = __ENV.K6_BEARER_TOKEN || "";

export default function () {
  const payload = JSON.stringify({
    tenant_id: tenantId,
    user_id: userId,
    channel,
    content,
  });
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (bearerToken) {
    headers.Authorization = `Bearer ${bearerToken}`;
  }
  const res = http.post(`${gatewayHttpBase}/v1/notifications`, payload, { headers });
  check(res, {
    "status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });
  sleep(1);
}
