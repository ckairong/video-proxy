const http = require("http");
const https = require("https");

const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const REFERER = "https://huangguoai.com/";
const PORT = process.env.PORT || 3000;

function fetchUpstream(targetUrl, extraHeaders) {
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(u, {
      headers: { "User-Agent": UA, "Referer": REFERER, ...(extraHeaders || {}) },
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

// ---- 臻美视界 _guard 会话通道: 上游全站加了 JS 盾 (guard/guardret cookie 校验,
// 且校验与出口 IP 绑定, Cloudflare 出口轮换过不了)。本通道在 LC 单一出口维护 cookie 罐,
// 按 _guard/auto.js 的算法完成握手: guardret = AES-128-CBC(key=iv=MD5(guard[0:8]))
// 加密 (解密(guard[12:]) 得到的数字 + 10)。响应体仍是上游的 AES 加密 JSON, 由调用方解密。
const crypto = require("crypto");
const ZM_SITE = "https://u4x28b.xxsxlr.top";
const ZM_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const zmJar = new Map();
let zmHandshakeInFlight = null;

function zmFetchRaw(apiPath, withCookies) {
  return new Promise((resolve, reject) => {
    const u = new URL(ZM_SITE + "/api" + apiPath);
    const headers = { "User-Agent": ZM_UA, "Referer": ZM_SITE + "/", "Accept": "application/json,text/html,*/*" };
    if (withCookies && zmJar.size) headers["Cookie"] = [...zmJar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    const req = https.request(u, { headers, timeout: 25000 }, (up) => {
      const setCookies = up.headers["set-cookie"] || [];
      for (const sc of setCookies) {
        const pair = sc.split(";")[0];
        const eq = pair.indexOf("=");
        if (eq > 0) zmJar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }
      const chunks = [];
      up.on("data", (c) => chunks.push(c));
      up.on("end", () => resolve({ status: up.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.end();
  });
}

async function zmHandshake(apiPath) {
  zmJar.delete("guard");
  zmJar.delete("guardret");
  await zmFetchRaw(apiPath, false);
  const guard = zmJar.get("guard");
  if (!guard || guard.length < 13) return false;
  const key = crypto.createHash("md5").update(guard.slice(0, 8), "utf8").digest();
  try {
    const d = crypto.createDecipheriv("aes-128-cbc", key, key);
    const plain = Buffer.concat([d.update(Buffer.from(guard.slice(12), "base64")), d.final()]).toString("utf8");
    const n = parseInt(plain, 10);
    if (Number.isNaN(n)) return false;
    const c = crypto.createCipheriv("aes-128-cbc", key, key);
    const ret = Buffer.concat([c.update(String(n + 10), "utf8"), c.final()]).toString("base64");
    zmJar.set("guardret", ret);
    return true;
  } catch (e) {
    return false;
  }
}

function zmHandshakeOnce(apiPath) {
  if (!zmHandshakeInFlight) {
    zmHandshakeInFlight = zmHandshake(apiPath).finally(() => { zmHandshakeInFlight = null; });
  }
  return zmHandshakeInFlight;
}

async function zmApi(apiPath) {
  let r = await zmFetchRaw(apiPath, true);
  if (r.body.includes("_guard")) {
    const ok = await zmHandshakeOnce(apiPath);
    if (!ok) return r;
    r = await zmFetchRaw(apiPath, true);
  }
  return r;
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
  if (url.pathname === "/zm") {
    const p = url.searchParams.get("path");
    if (!p || !p.startsWith("/")) { res.writeHead(400); res.end("Bad path"); return; }
    try {
      const r = await zmApi(p);
      res.writeHead(r.status, { "content-type": "application/json", "Access-Control-Allow-Origin": "*", "Cache-Control": "no-store" });
      res.end(r.body);
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
      // 可选 Range 透传 (?range=bytes=x-y): 大文件分段取流 (如 mp4 中转) 需要,
      // 带上后上游返回 206 与 content-range, 一并回传给调用方。
      // 可选 Referer 覆盖 (?ref=<url>): 个别站点按 Referer 决定返回内容
      // (如 avtoday 播放页, Referer 不对会跳回首页)。
      const range = url.searchParams.get("range");
      const ref = url.searchParams.get("ref");
      const extra = {};
      if (range) extra.Range = range;
      if (ref) extra.Referer = ref;
      const up = await fetchUpstream(target.toString(), Object.keys(extra).length ? extra : undefined);
      const ct = up.headers["content-type"];
      const headers = {
        ...(ct ? { "content-type": ct } : {}),
        "Access-Control-Allow-Origin": "*",
        "Cache-Control": "public, max-age=3600",
      };
      for (const h of ["content-range", "accept-ranges", "content-length"]) {
        if (up.headers[h]) headers[h] = up.headers[h];
      }
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
