import { WebSocket, WebSocketServer } from "ws";
import express from "express";
import { createHmac } from "crypto";
import * as jose from "jose";
import { prisma } from "./db";
import { NotFoundError, UnauthorizedError, UnprocessableEntityError } from "./errors";
import { activeConnections, iceServers, inFlight } from "./webrtc-signaling";

export const CreateSession = async (req: express.Request, res: express.Response) => {
  const idToken = req.session?.id_token;
  const { sub } = jose.decodeJwt(idToken);

  const { id, sd } = req.body;

  if (!id) throw new UnprocessableEntityError("Missing id");
  if (!sd) throw new UnprocessableEntityError("Missing sd");

  const device = await prisma.device.findUnique({
    where: { id, user: { googleId: sub } },
    select: { id: true },
  });

  if (!device) {
    throw new NotFoundError("Device not found");
  }

  if (inFlight.has(id)) {
    console.log(`Websocket for ${id} in-flight with another client`);
    throw new UnprocessableEntityError(
      `Websocket for ${id} in-flight with another client`,
    );
  }

  const deviceConn = activeConnections.get(id);
  if (!deviceConn) {
    console.log("No socket for id", id);
    throw new NotFoundError(`No socket for id found`, "kvm_socket_not_found");
  }

  const { ws, ip } = deviceConn;

  let timeout: NodeJS.Timeout | undefined;

  let httpClose: (() => void) | null = null;

  try {
    inFlight.add(id);
    const resp: any = await new Promise((res, rej) => {
      timeout = setTimeout(() => {
        rej(new Error("Timeout waiting for response from ws"));
      }, 15000);

      ws.onerror = rej;
      ws.onclose = rej;
      ws.onmessage = res;

      httpClose = () => {
        rej(new Error("HTTP client closed the connection"));
      };

      // If the HTTP client closes the connection before the websocket response is received, reject the promise
      req.socket.on("close", httpClose);

      ws.send(
        JSON.stringify({
          sd,
          ip,
          iceServers,
          OidcGoogle: idToken,
        }),
      );
    });

    console.log("[CreateSession] got response from device", id);
    return res.json(JSON.parse(resp.data));
  } catch (e) {
    console.log(`Error sending data to kvm with ${id}`, e);

    return res
      .status(500)
      .json({ error: "There was an error sending and receiving data to the KVM" });
  } finally {
    if (timeout) clearTimeout(timeout);
    console.log("Removing in flight", id);
    inFlight.delete(id);

    if (httpClose) {
      console.log("Removing http close listener", id);
      req.socket.off("close", httpClose);
    }

    if (ws) {
      console.log("Removing ws listeners", id);
      ws.onerror = null;
      ws.onclose = null;
      ws.onmessage = null;
    }
  }
};

/**
 * Short-lived credentials for a self-hosted coturn server running with `use-auth-secret`
 * (the "TURN REST API" scheme): username = "<expiry unix time>:<user id>",
 * credential = base64(HMAC-SHA1(shared secret, username)). coturn checks both itself, so
 * the shared secret never leaves the API. Returns null when TURN_URLS / TURN_SHARED_SECRET
 * are not set, so Cloudflare (CLOUDFLARE_TURN_ID / CLOUDFLARE_TURN_TOKEN) is used as before.
 */
export const coturnIceServers = (userId: string, ttlSeconds = 3600) => {
  const urls = (process.env.TURN_URLS || "")
    .split(",")
    .map(url => url.trim())
    .filter(url => /^(turn|turns|stun):/.test(url));
  const secret = process.env.TURN_SHARED_SECRET;
  if (!secret || !urls.some(url => url.startsWith("turn"))) return null;

  const username = `${Math.floor(Date.now() / 1000) + ttlSeconds}:${userId}`;
  const credential = createHmac("sha1", secret).update(username).digest("base64");
  return { urls, username, credential };
};

export const CreateIceCredentials = async (
  req: express.Request,
  res: express.Response,
) => {
  const { sub } = jose.decodeJwt(req.session?.id_token);
  if (!sub) throw new UnauthorizedError();

  const user = await prisma.user.findUnique({
    where: { googleId: sub },
    select: { id: true },
  });
  if (!user) throw new UnauthorizedError();

  // Self-hosted coturn (e.g. the TURN VM in Azure) takes precedence over Cloudflare.
  const coturn = coturnIceServers(user.id.toString());
  if (coturn) {
    return res.json({ iceServers: coturn });
  }

  const resp = await fetch(
    `https://rtc.live.cloudflare.com/v1/turn/keys/${process.env.CLOUDFLARE_TURN_ID}/credentials/generate`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.CLOUDFLARE_TURN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ttl: 3600, customIdentifier: user.id.toString() }),
    },
  );

  const data = (await resp.json()) as {
    iceServers: { credential?: string; urls: string | string[]; username?: string };
  };

  if (!data.iceServers.urls) {
    throw new Error("No ice servers returned");
  }

  if (data.iceServers.urls instanceof Array) {
    data.iceServers.urls = data.iceServers.urls.filter(url => !url.startsWith("turns"));
  }

  return res.json(data);
};

export const CreateTurnActivity = async (req: express.Request, res: express.Response) => {
  const idToken = req.session?.id_token;
  const { sub } = jose.decodeJwt(idToken);
  const { bytesReceived, bytesSent } = req.body;

  await prisma.turnActivity.create({
    data: {
      bytesReceived,
      bytesSent,
      user: { connect: { googleId: sub } },
    },
  });

  return res.json({ success: true });
};
