const http = require("http");
const https = require("https");

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const REFERER = "https://huangguoai.com/";
const PORT = process.env.PORT || 3000;

function fetchUpstream(targetUrl) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, {
      headers: { "User-Agent": UA, "Referer": REFERER },
      timeout: 25000,
    }, (res) => resolve(res));
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.end();
  });
}

/** 通用转发（用于 IMA API 中转）：只透传指定 header，不落地存储 */
function relayRequest(targetUrl, method, headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, { method, headers, timeout: 30000 }, (res) => resolve(res));
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    if (body && body.length) req.write(body);
    req.end();
  });
}

const IMA_FORWARD_HEADERS = ["ima-openapi-clientid", "ima-openapi-apikey", "ima-openapi-ctx", "content-type"];

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === "/raw") {
    const u = url.searchParams.get("u");
    if (!u) { res.writeHead(400); res.end("Missing u"); return; }
    let target;
    try { target = new URL(u); } catch { res.writeHead(400); res.end("Bad url"); return; }
    if (target.protocol !== "https:") { res.writeHead(400); res.end("https only"); return; }
    try {
      const up = await fetchUpstream(target.toString());
      const ct = up.headers["content-type"];
      res.writeHead(up.statusCode, {
        ...(ct ? { "content-type": ct } : {}),
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "public, max-age=3600",
      });
      up.pipe(res);
    } catch (e) {
      res.writeHead(502); res.end("Upstream error");
    }
    return;
  }
  if (url.pathname === "/health") { res.writeHead(200); res.end("ok"); return; }
  // IMA API 中转：POST /ima/<apiPath>，header 透传（密钥不落地）
  if (url.pathname.startsWith("/ima/")) {
    const apiPath = url.pathname.slice(5);
    if (!apiPath || apiPath.includes("..")) { res.writeHead(400); res.end("Bad path"); return; }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      try {
        const fwd = {};
        for (const h of IMA_FORWARD_HEADERS) {
          const v = req.headers[h];
          if (v) fwd[h] = v;
        }
        fwd["User-Agent"] = UA;
        const up = await relayRequest(
          "https://ima.qq.com/" + apiPath + url.search,
          req.method, fwd, Buffer.concat(chunks)
        );
        const ct = up.headers["content-type"] || "application/json";
        res.writeHead(up.statusCode, { "content-type": ct, "Access-Control-Allow-Origin": "*" });
        up.pipe(res);
      } catch (e) { res.writeHead(502); res.end("Relay error"); }
    });
    return;
  }
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("video-proxy running");
});

server.listen(PORT, () => console.log("listening on " + PORT));
