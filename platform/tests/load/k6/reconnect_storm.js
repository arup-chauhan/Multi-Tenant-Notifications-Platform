import ws from "k6/ws";
import { sleep } from "k6";

export const options = {
  vus: 100,
  duration: "90s",
};

export default function () {
  ws.connect("ws://localhost:8080/ws", {}, function (socket) {
    socket.setTimeout(function () {
      socket.close();
    }, 2000);
  });

  sleep(0.5);
}
