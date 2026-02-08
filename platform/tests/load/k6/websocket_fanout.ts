import ws from "k6/ws";
import { check } from "k6";

export const options = {
  vus: 50,
  duration: "2m",
};

export default function () {
  const url = "ws://localhost:8080/ws";
  const response = ws.connect(url, {}, function (socket) {
    socket.on("open", () => {
      socket.send(JSON.stringify({ type: "subscribe", channel: "alerts" }));
    });
    socket.on("message", () => {});
    socket.setTimeout(function () {
      socket.close();
    }, 10000);
  });

  check(response, { "status is 101": (r) => r && r.status === 101 });
}
