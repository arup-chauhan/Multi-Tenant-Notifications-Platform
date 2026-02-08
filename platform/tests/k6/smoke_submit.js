import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 1,
  iterations: 1,
};

export default function () {
  const payload = JSON.stringify({
    tenant_id: "tenant-demo",
    user_id: "user-1",
    content: "smoke notification",
  });
  const params = { headers: { "Content-Type": "application/json" } };
  const res = http.post("http://localhost:8080/v1/notifications", payload, params);
  check(res, {
    "status is 2xx": (r) => r.status >= 200 && r.status < 300,
  });
  sleep(1);
}
