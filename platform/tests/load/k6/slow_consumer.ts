import ws from "k6/ws";
import { sleep } from "k6";

export const options = {
  vus: 25,
  duration: "2m",
};

const gatewayWsUrl = __ENV.GATEWAY_WS_URL || "ws://localhost:8080/ws";

export default function () {
  ws.connect(gatewayWsUrl, {}, function (socket) {
    socket.on("message", () => {
      // Simulate slow message handling on client side.
      sleep(0.25);
    });
    socket.setTimeout(function () {
      socket.close();
    }, 15000);
  });
}
