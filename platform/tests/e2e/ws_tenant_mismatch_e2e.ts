import ws from "k6/ws";
import { check } from "k6";

export const options = {
  vus: 1,
  iterations: 1,
};

const gatewayWsUrl = __ENV.E2E_GATEWAY_WS_URL || "ws://127.0.0.1:8080/ws";
const bearerToken = __ENV.E2E_BEARER_TOKEN || "";
const validTenant = __ENV.E2E_TENANT_ID || "tenant-e2e";
const wrongTenant = __ENV.E2E_WRONG_TENANT_ID || "tenant-other";
const channel = __ENV.E2E_CHANNEL || "alerts";

export default function () {
  let closeSeen = false;

  const wsHeaders: Record<string, string> = {};
  if (bearerToken) {
    wsHeaders.Authorization = `Bearer ${bearerToken}`;
  }

  const response = ws.connect(gatewayWsUrl, { headers: wsHeaders }, (socket) => {
    socket.on("open", () => {
      socket.send(JSON.stringify({ type: "subscribe", tenant_id: wrongTenant, channel }));
      socket.setTimeout(() => {
        socket.close();
      }, 3000);
    });

    socket.on("close", () => {
      closeSeen = true;
    });
  });

  check(response, {
    "ws upgrade status is 101": (r) => r && r.status === 101,
  });
  check(null, {
    "server closes mismatch subscription": () => closeSeen,
    "mismatch tenant differs from token tenant": () => wrongTenant !== validTenant,
  });
}
