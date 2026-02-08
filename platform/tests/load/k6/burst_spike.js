import http from "k6/http";
import { check } from "k6";

export const options = {
  stages: [
    { duration: "30s", target: 10 },
    { duration: "30s", target: 200 },
    { duration: "30s", target: 10 },
  ],
};

export default function () {
  const payload = JSON.stringify({
    tenant_id: "tenant-b",
    user_id: "user-spike",
    channel: "critical",
    content: "burst traffic notification",
  });

  const res = http.post("http://localhost:8080/v1/notifications", payload, {
    headers: { "Content-Type": "application/json" },
  });

  check(res, { "status 2xx": (r) => r.status >= 200 && r.status < 300 });
}
