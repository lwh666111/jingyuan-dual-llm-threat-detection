const http = require("http");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const HOST = process.env.DASHBOARD_HOST || "0.0.0.0";
const PORT = Number(process.env.DASHBOARD_PORT || 1145);
const API_BASE = process.env.API_BASE || "http://127.0.0.1:3049";
const PUBLIC_DIR = path.join(__dirname, "public");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".svg": "image/svg+xml",
};

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
  });
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function proxyRequest(req, res, upstreamPath, searchParams) {
  const target = new URL(upstreamPath, API_BASE);
  for (const [k, v] of searchParams.entries()) {
    target.searchParams.set(k, v);
  }

  try {
    const bodyBuffer = req.method === "GET" || req.method === "HEAD" ? null : await readBody(req);
    const headers = {
      Accept: req.headers.accept || "application/json",
    };
    if (req.headers.authorization) {
      headers.Authorization = req.headers.authorization;
    }
    if (req.headers["content-type"]) {
      headers["Content-Type"] = req.headers["content-type"];
    }

    const upstream = await fetch(target.toString(), {
      method: req.method || "GET",
      headers,
      body: bodyBuffer && bodyBuffer.length > 0 ? bodyBuffer : undefined,
    });

    const outputHeaders = {
      "Content-Type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
    };
    const contentDisposition = upstream.headers.get("content-disposition");
    if (contentDisposition) {
      outputHeaders["Content-Disposition"] = contentDisposition;
    }

    const data = Buffer.from(await upstream.arrayBuffer());
    res.writeHead(upstream.status, outputHeaders);
    res.end(data);
  } catch (err) {
    sendJson(res, 502, { error: "upstream_unreachable", detail: String(err) });
  }
}

function serveStatic(reqPath, res) {
  const relative = reqPath === "/" ? "/index.html" : reqPath;
  const safePath = path.normalize(relative).replace(/^(\.\.[/\\])+/, "");
  const fullPath = path.join(PUBLIC_DIR, safePath);

  if (!fullPath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: "forbidden" });
    return;
  }

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      sendJson(res, 404, { error: "not_found" });
      return;
    }
    const ext = path.extname(fullPath).toLowerCase();
    const contentType = MIME_TYPES[ext] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);

  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    });
    return res.end();
  }

  if (reqUrl.pathname.startsWith("/api/v1/") || reqUrl.pathname.startsWith("/api/v2/")) {
    return proxyRequest(req, res, reqUrl.pathname, reqUrl.searchParams);
  }

  if (reqUrl.pathname === "/api/health") {
    return proxyRequest(req, res, "/api/v1/screen/ping", reqUrl.searchParams);
  }
  if (reqUrl.pathname === "/api/attacks") {
    return proxyRequest(req, res, "/api/v1/screen/attacks", reqUrl.searchParams);
  }
  if (reqUrl.pathname === "/api/request-body") {
    return proxyRequest(req, res, "/api/v1/screen/request-body", reqUrl.searchParams);
  }
  if (reqUrl.pathname === "/api/response-body") {
    return proxyRequest(req, res, "/api/v1/screen/response-body", reqUrl.searchParams);
  }

  if (req.method === "GET") {
    return serveStatic(reqUrl.pathname, res);
  }

  sendJson(res, 405, { error: "method_not_allowed" });
});

server.listen(PORT, HOST, () => {
  console.log(`[dashboard] running at http://${HOST}:${PORT}`);
  console.log(`[dashboard] upstream api: ${API_BASE}`);
});
