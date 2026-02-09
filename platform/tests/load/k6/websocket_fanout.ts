import ws from "k6/ws";
import { check } from "k6";

export const options = {
  vus: 50,
  duration: "2m",
};

const gatewayWsUrl = __ENV.GATEWAY_WS_URL || "ws://localhost:8080/ws";

export default function () {
  const tenantId = `tenant-${__VU % 5}`;
  const response = ws.connect(gatewayWsUrl, {}, function (socket) {
    socket.on("open", () => {
      socket.send(JSON.stringify({ type: "subscribe", tenant_id: tenantId, channel: "alerts" }));
    });
    socket.on("message", () => {});
    socket.setTimeout(function () {
      socket.close();
    }, 10000);
  });

  check(response, { "status is 101": (r) => r && r.status === 101 });
}
