import ws from "k6/ws";
import { sleep } from "k6";

export const options = {
  vus: 25,
  duration: "2m",
};

export default function () {
  ws.connect("ws://localhost:8080/ws", {}, function (socket) {
    socket.on("message", () => {
      // Simulate slow message handling on client side.
      sleep(0.25);
    });
    socket.setTimeout(function () {
      socket.close();
    }, 15000);
  });
}
