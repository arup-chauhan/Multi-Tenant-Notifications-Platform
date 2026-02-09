import ws from "k6/ws";
import { sleep } from "k6";

export const options = {
  vus: 100,
  duration: "90s",
};

const gatewayWsUrl = __ENV.GATEWAY_WS_URL || "ws://localhost:8080/ws";

export default function () {
  ws.connect(gatewayWsUrl, {}, function (socket) {
    socket.setTimeout(function () {
      socket.close();
    }, 2000);
  });

  sleep(0.5);
}
