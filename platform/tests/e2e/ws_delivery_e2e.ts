import http from "k6/http";
import ws from "k6/ws";
import { check } from "k6";

export const options = {
  vus: 1,
  iterations: 1,
};

const gatewayHttpBase = __ENV.E2E_GATEWAY_HTTP_BASE || "http://127.0.0.1:8080";
const gatewayWsUrl = __ENV.E2E_GATEWAY_WS_URL || "ws://127.0.0.1:8080/ws";
const tenantId = __ENV.E2E_TENANT_ID || "tenant-e2e";
const userId = __ENV.E2E_USER_ID || "user-e2e";
const channel = __ENV.E2E_CHANNEL || "alerts";
const marker = __ENV.E2E_MARKER || "e2e-marker";

export default function () {
  let wsMessageSeen = false;
  let postAccepted = false;

  const wsResponse = ws.connect(gatewayWsUrl, {}, function (socket) {
    socket.on("open", () => {
      socket.send(JSON.stringify({ type: "subscribe", tenant_id: tenantId, channel }));

      const payload = JSON.stringify({
        tenant_id: tenantId,
        user_id: userId,
        channel,
        content: `e2e-${marker}`,
      });

      const response = http.post(`${gatewayHttpBase}/v1/notifications`, payload, {
        headers: { "Content-Type": "application/json" },
      });
      postAccepted = response.status === 202;

      socket.setTimeout(() => {
        socket.close();
      }, 8000);
    });

    socket.on("message", (msg) => {
      if (String(msg).includes(`e2e-${marker}`)) {
        wsMessageSeen = true;
        socket.close();
      }
    });
  });

  check(wsResponse, { "ws upgrade status is 101": (r) => r && r.status === 101 });
  check(null, { "notification POST accepted (202)": () => postAccepted });
  check(null, { "websocket delivery received": () => wsMessageSeen });
}
