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

// ---- Pornhub 专用会话通道: hv-h.phncdn.com 的签名地址除 IP 绑定外还校验页面会话 Cookie,
// 必须由同一出口先取页面存下 Cookie, 再带 Cookie 取流。会话只存内存, 2 小时过期。
const PH_SESSIONS = new Map(); // id -> { jar: Map<name, value>, at: number }
const PH_TTL = 2 * 3600 * 1000;

function phFetch(targetUrl, jar) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const lib = u.protocol === "https:" ? https : http;
    const headers = {
      "User-Agent": UA,
      "Referer": "https://www.pornhub.com/",
      "Accept-Language": "en-US,en;q=0.9",
    };
    if (jar && jar.size) {
      headers["Cookie"] = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    }
    const req = lib.request(u, { headers, timeout: 25000 }, (up) => {
      if (jar) {
        const setCookies = up.headers["set-cookie"] || [];
        for (const sc of setCookies) {
          const pair = sc.split(";")[0];
          const eq = pair.indexOf("=");
          if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
        }
      }
      // 跟随跳转 (带 Cookie)
      if (up.statusCode >= 300 && up.statusCode < 400 && up.headers.location) {
        up.resume();
        resolve(phFetch(new URL(up.headers.location, u).toString(), jar));
        return;
      }
      resolve(up);
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === "/ph/page" || url.pathname === "/ph/res") {
    const u = url.searchParams.get("u");
    if (!u) { res.writeHead(400); res.end("Missing u"); return; }
    let target;
    try { target = new URL(u); } catch { res.writeHead(400); res.end("Bad url"); return; }
    if (!/(^|\.)pornhub\.com$|(^|\.)phncdn\.com$/.test(target.hostname)) {
      res.writeHead(403); res.end("host not allowed"); return;
    }
    try {
      let jar;
      let sid = url.searchParams.get("s");
      if (url.pathname === "/ph/page") {
        sid = Math.random().toString(36).slice(2) + Date.now().toString(36);
        jar = new Map();
        PH_SESSIONS.set(sid, { jar, at: Date.now() });
        // 顺手清理过期会话
        for (const [k, v] of PH_SESSIONS) if (Date.now() - v.at > PH_TTL) PH_SESSIONS.delete(k);
      } else {
        const sess = sid ? PH_SESSIONS.get(sid) : null;
        jar = sess ? sess.jar : new Map();
        if (sess) sess.at = Date.now();
      }
      const up = await phFetch(target.toString(), jar);
      const headers = {
        "content-type": up.headers["content-type"] || "application/octet-stream",
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "no-store",
      };
      if (url.pathname === "/ph/page") headers["x-ph-session"] = sid;
      if (up.headers["content-range"]) headers["content-range"] = up.headers["content-range"];
      if (up.headers["content-length"]) headers["content-length"] = up.headers["content-length"];
      res.writeHead(up.statusCode, headers);
      up.pipe(res);
    } catch (e) {
      res.writeHead(502); res.end("Upstream error");
    }
    return;
  }
  if (url.pathname === "/raw") {
    const u = url.searchParams.get("u");
    if (!u) { res.writeHead(400); res.end("Missing u"); return; }
    let target;
    try { target = new URL(u); } catch { res.writeHead(400); res.end("Bad url"); return; }
    if (target.protocol !== "https:" && target.protocol !== "http:") { res.writeHead(400); res.end("http(s) only"); return; }
    try {
      const up = await fetchUpstream(target.toString());
      const ct = up.headers["content-type"];
      const headers = {
        ...(ct ? { "content-type": ct } : {}),
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "public, max-age=3600",
      };
      // 转发 302 的 Location（上游 php 解析类地址依赖它），否则跟随跳转会断掉
      const loc = up.headers["location"];
      if (loc) headers["location"] = loc;
      res.writeHead(up.statusCode, headers);
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
