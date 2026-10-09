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
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("video-proxy running");
});

server.listen(PORT, () => console.log("listening on " + PORT));
