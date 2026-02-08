import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 20,
  duration: "5m",
};

export default function () {
  const payload = JSON.stringify({
    tenant_id: "tenant-a",
    user_id: "user-1",
    channel: "alerts",
    content: "steady-state notification",
  });

  const res = http.post("http://localhost:8080/v1/notifications", payload, {
    headers: { "Content-Type": "application/json" },
  });

  check(res, { "status 2xx": (r) => r.status >= 200 && r.status < 300 });
  sleep(0.2);
}
