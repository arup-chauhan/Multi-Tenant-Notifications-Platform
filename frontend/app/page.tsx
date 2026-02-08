"use client";

import { useEffect, useMemo, useRef, useState } from "react";

type ConnectionState = "connecting" | "open" | "closed" | "error";

const httpBase = process.env.NEXT_PUBLIC_GATEWAY_HTTP_BASE ?? "http://localhost:8080";
const wsBase = process.env.NEXT_PUBLIC_GATEWAY_WS_BASE ?? "ws://localhost:8080/ws";

export default function Page(): JSX.Element {
  const [tenantId, setTenantId] = useState("tenant-a");
  const [userId, setUserId] = useState("u1");
  const [channel, setChannel] = useState("alerts");
  const [content, setContent] = useState("");
  const [statusText, setStatusText] = useState("idle");
  const [connectionState, setConnectionState] = useState<ConnectionState>("closed");
  const [messages, setMessages] = useState<string[]>([]);

  const socketRef = useRef<WebSocket | null>(null);

  const connectLabel = useMemo(() => {
    switch (connectionState) {
      case "open":
        return "Connected";
      case "connecting":
        return "Connecting";
      case "error":
        return "Error";
      default:
        return "Disconnected";
    }
  }, [connectionState]);

  useEffect(() => {
    return () => {
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, []);

  function connectWs(): void {
    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      return;
    }

    setConnectionState("connecting");
    const ws = new WebSocket(wsBase);
    socketRef.current = ws;

    ws.onopen = () => {
      setConnectionState("open");
      ws.send(
        JSON.stringify({
          type: "subscribe",
          tenant_id: tenantId,
          channel
        })
      );
      setMessages((prev) => [`[system] websocket connected to ${wsBase}`, ...prev]);
    };

    ws.onmessage = (event) => {
      setMessages((prev) => [String(event.data), ...prev]);
    };

    ws.onerror = () => {
      setConnectionState("error");
      setMessages((prev) => ["[system] websocket error", ...prev]);
    };

    ws.onclose = () => {
      setConnectionState("closed");
      setMessages((prev) => ["[system] websocket disconnected", ...prev]);
    };
  }

  function disconnectWs(): void {
    socketRef.current?.close();
    socketRef.current = null;
    setConnectionState("closed");
  }

  async function submitNotification(event: React.FormEvent): Promise<void> {
    event.preventDefault();
    setStatusText("submitting");

    try {
      const response = await fetch(`${httpBase}/v1/notifications`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          tenant_id: tenantId,
          user_id: userId,
          channel,
          content
        })
      });

      const body = (await response.text()) || "";
      if (!response.ok) {
        setStatusText(`error ${response.status}: ${body}`);
        return;
      }

      setStatusText(`accepted ${response.status}: ${body}`);
      setContent("");
    } catch (error) {
      setStatusText(`request failed: ${(error as Error).message}`);
    }
  }

  return (
    <div className="layout">
      <main className="panel left-panel">
        <h1>Multi-Tenant Notification Platform</h1>
        <p className="subtitle">Next.js + TypeScript operator console</p>

        <form className="form" onSubmit={submitNotification}>
          <label>
            Tenant ID
            <input value={tenantId} onChange={(e) => setTenantId(e.target.value)} required />
          </label>

          <label>
            User ID
            <input value={userId} onChange={(e) => setUserId(e.target.value)} required />
          </label>

          <label>
            Channel
            <input value={channel} onChange={(e) => setChannel(e.target.value)} required />
          </label>

          <label>
            Content
            <textarea value={content} onChange={(e) => setContent(e.target.value)} required rows={4} />
          </label>

          <button type="submit">Send Notification</button>
        </form>

        <p className="status">HTTP Status: {statusText}</p>
      </main>

      <aside className="panel right-panel">
        <div className="ws-header">
          <h2>Realtime Feed</h2>
          <span className={`badge ${connectionState}`}>{connectLabel}</span>
        </div>

        <div className="ws-actions">
          <button onClick={connectWs}>Connect WS</button>
          <button onClick={disconnectWs}>Disconnect WS</button>
        </div>

        <div className="feed" role="log" aria-live="polite">
          {messages.length === 0 ? <p className="empty">No events yet.</p> : null}
          {messages.map((msg, index) => (
            <div key={`${msg}-${index}`} className="message">
              {msg}
            </div>
          ))}
        </div>
      </aside>
    </div>
  );
}
