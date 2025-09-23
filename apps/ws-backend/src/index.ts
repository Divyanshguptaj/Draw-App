import { WebSocketServer } from "ws";
import jwt, { JwtPayload } from "jsonwebtoken";
import {JWT_SECRET} from '@repo/backend-common/config'
const wss = new WebSocketServer({ port: 4000 });

wss.on("connection", (ws, request) => {
  // console.log("New client connected");
  const url = request.url || "";
  const queryParams = new URLSearchParams(url.split("?")[1]);
  const token = queryParams.get("token") || "";
  const decoded = jwt.verify(token, JWT_SECRET as any);
  if(!decoded || (!(decoded as JwtPayload).userId)){
    ws.close();
    return;
  }
  ws.on("message", (message) => {
    console.log(`Received message: ${message}`);
  });

  ws.on("close", () => {
    console.log("Client disconnected");
  });
});
