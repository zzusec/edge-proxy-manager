const PROXY_KEY_PREFIX = "proxy:";
const SESSION_COOKIE = "__Host-edge_proxy_session";
const SESSION_MAX_AGE = 8 * 60 * 60;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const adminHostname = normalizeHostname(env.ADMIN_HOSTNAME);

    if (adminHostname && url.hostname === adminHostname) {
      return handleAdminRequest(request, env, url);
    }

    return handleProxyRequest(request, env, url);
  },
};

async function handleAdminRequest(request, env, url) {
  const configError = getAdminConfigError(env);

  if (configError) {
    return htmlResponse(configurationErrorPage(configError), 500);
  }

  if (url.pathname === "/login" && request.method === "GET") {
    if (await isAuthenticated(request, env)) {
      return redirectTo(url, "/");
    }

    return htmlResponse(loginPage());
  }

  if (url.pathname === "/login" && request.method === "POST") {
    if (!isSameOriginRequest(request, url)) {
      return htmlResponse(loginPage("请求来源验证失败"), 403);
    }

    let form;

    try {
      form = await request.formData();
    } catch {
      return htmlResponse(loginPage("登录请求格式无效"), 400);
    }

    const username = String(form.get("username") || "");
    const password = String(form.get("password") || "");
    const [usernameMatches, passwordMatches] = await Promise.all([
      secureEqual(username, env.ADMIN_USERNAME, env.SESSION_SECRET),
      secureEqual(password, env.ADMIN_PASSWORD, env.SESSION_SECRET),
    ]);

    if (!usernameMatches || !passwordMatches) {
      return htmlResponse(loginPage("用户名或密码错误"), 401);
    }

    const sessionToken = await createSessionToken(env);
    const response = redirectTo(url, "/");
    response.headers.set(
      "Set-Cookie",
      `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`,
    );
    return response;
  }

  if (url.pathname === "/logout" && request.method === "POST") {
    if (!isSameOriginRequest(request, url)) {
      return new Response("Forbidden", { status: 403 });
    }

    const response = redirectTo(url, "/login");
    response.headers.set(
      "Set-Cookie",
      `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
    );
    return response;
  }

  const authenticated = await isAuthenticated(request, env);

  if (!authenticated) {
    if (url.pathname.startsWith("/api/")) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    return redirectTo(url, "/login");
  }

  if (url.pathname === "/" && request.method === "GET") {
    return htmlResponse(dashboardPage(env.ADMIN_USERNAME), 200, true);
  }

  if (url.pathname === "/api/proxies" && request.method === "GET") {
    const proxies = await listProxyConfigs(env.PROXY_CONFIG);
    return jsonResponse({ proxies });
  }

  if (url.pathname === "/api/proxies" && request.method === "POST") {
    if (!isSameOriginRequest(request, url)) {
      return jsonResponse({ error: "Forbidden" }, 403);
    }

    let input;

    try {
      input = await request.json();
    } catch {
      return jsonResponse({ error: "请求数据不是有效 JSON" }, 400);
    }

    const validation = validateProxyConfig(input);

    if (validation.error) {
      return jsonResponse({ error: validation.error }, 400);
    }

    const originalDomain = normalizeHostname(input.originalDomain);
    const existingDomain = originalDomain || validation.config.domain;
    const existing = await env.PROXY_CONFIG.get(
      `${PROXY_KEY_PREFIX}${existingDomain}`,
      "json",
    );
    const now = new Date().toISOString();
    const config = {
      ...validation.config,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
    };

    await env.PROXY_CONFIG.put(
      `${PROXY_KEY_PREFIX}${config.domain}`,
      JSON.stringify(config),
    );

    if (originalDomain && originalDomain !== config.domain) {
      await env.PROXY_CONFIG.delete(`${PROXY_KEY_PREFIX}${originalDomain}`);
    }

    return jsonResponse({ proxy: config });
  }

  if (url.pathname.startsWith("/api/proxies/") && request.method === "DELETE") {
    if (!isSameOriginRequest(request, url)) {
      return jsonResponse({ error: "Forbidden" }, 403);
    }

    const domain = normalizeHostname(
      decodeURIComponent(url.pathname.slice("/api/proxies/".length)),
    );

    if (!isValidHostname(domain)) {
      return jsonResponse({ error: "域名格式无效" }, 400);
    }

    await env.PROXY_CONFIG.delete(`${PROXY_KEY_PREFIX}${domain}`);
    return jsonResponse({ deleted: domain });
  }

  return new Response("Not Found", { status: 404 });
}

async function handleProxyRequest(request, env, incomingUrl) {
  if (!env.PROXY_CONFIG?.get) {
    return new Response("Proxy configuration storage is unavailable", {
      status: 503,
    });
  }

  const hostname = normalizeHostname(incomingUrl.hostname);
  const config = await env.PROXY_CONFIG.get(
    `${PROXY_KEY_PREFIX}${hostname}`,
    "json",
  );

  if (!config?.enabled) {
    return new Response("Proxy host not configured", { status: 404 });
  }

  if (config.forceHttps && incomingUrl.protocol === "http:") {
    const httpsUrl = new URL(incomingUrl);
    httpsUrl.protocol = "https:";
    return Response.redirect(httpsUrl.toString(), 308);
  }

  if (config.blockExploits && isSuspiciousPath(incomingUrl.pathname)) {
    return new Response("Forbidden", { status: 403 });
  }

  const websocketRequest =
    request.headers.get("Upgrade")?.toLowerCase() === "websocket";

  if (websocketRequest && !config.websocket) {
    return new Response("WebSocket proxying is disabled", { status: 426 });
  }

  if (incomingUrl.pathname === "/" && config.landingPath) {
    const landingUrl = new URL(config.landingPath, incomingUrl.origin);
    landingUrl.search = incomingUrl.search;
    landingUrl.hash = config.landingHash || "";
    return Response.redirect(landingUrl.toString(), 302);
  }

  const targetOrigin = selectTargetOrigin(config, incomingUrl.pathname);

  if (!targetOrigin) {
    return new Response("Invalid proxy configuration", { status: 502 });
  }

  const upstreamUrl = new URL(
    incomingUrl.pathname + incomingUrl.search,
    `${targetOrigin}/`,
  );
  const headers = new Headers(request.headers);
  const upstreamHost = upstreamUrl.host;

  headers.delete("host");
  headers.set("Host", upstreamHost);
  headers.set("X-Forwarded-Host", incomingUrl.host);
  headers.set("X-Forwarded-Proto", incomingUrl.protocol.slice(0, -1));

  const clientIp = request.headers.get("CF-Connecting-IP");
  if (clientIp) {
    headers.set("X-Forwarded-For", clientIp);
  }

  if (headers.get("Origin") === incomingUrl.origin) {
    headers.set("Origin", targetOrigin);
  }

  const referer = headers.get("Referer");
  if (referer?.startsWith(`${incomingUrl.origin}/`)) {
    headers.set("Referer", referer.replace(incomingUrl.origin, targetOrigin));
  }

  const requestInit = {
    method: request.method,
    headers,
    redirect: "manual",
  };

  if (request.method !== "GET" && request.method !== "HEAD") {
    requestInit.body = request.body;
  }

  let upstreamResponse;

  try {
    upstreamResponse = await fetch(new Request(upstreamUrl, requestInit));
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "proxy_fetch_failed",
        hostname,
        targetOrigin,
        message: error instanceof Error ? error.message : "Unknown error",
      }),
    );
    return new Response("Bad Gateway", { status: 502 });
  }

  if (websocketRequest) {
    return upstreamResponse;
  }

  const responseHeaders = new Headers(upstreamResponse.headers);
  const location = responseHeaders.get("Location");

  if (location) {
    try {
      const redirectUrl = new URL(location, upstreamUrl);

      if (redirectUrl.origin === targetOrigin) {
        const publicRedirectUrl = new URL(
          redirectUrl.pathname + redirectUrl.search,
          incomingUrl.origin,
        );
        publicRedirectUrl.hash = redirectUrl.hash;
        responseHeaders.set("Location", publicRedirectUrl.toString());
      }
    } catch {
      responseHeaders.delete("Location");
    }
  }

  rewriteCookieDomains(
    upstreamResponse.headers,
    responseHeaders,
    new URL(targetOrigin).hostname,
    incomingUrl.hostname,
  );

  if (config.hsts && incomingUrl.protocol === "https:") {
    responseHeaders.set("Strict-Transport-Security", "max-age=31536000");
  }

  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers: responseHeaders,
  });
}

function getAdminConfigError(env) {
  const missing = [];

  if (!normalizeHostname(env.ADMIN_HOSTNAME)) missing.push("ADMIN_HOSTNAME");
  if (!env.ADMIN_USERNAME) missing.push("ADMIN_USERNAME");
  if (!env.ADMIN_PASSWORD) missing.push("ADMIN_PASSWORD");
  if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
    missing.push("SESSION_SECRET（至少 32 个字符）");
  }
  if (!env.PROXY_CONFIG?.get || !env.PROXY_CONFIG?.put) {
    missing.push("PROXY_CONFIG KV 绑定");
  }

  return missing.length ? `缺少配置：${missing.join("、")}` : "";
}

async function listProxyConfigs(kv) {
  const proxies = [];
  let cursor;

  do {
    const page = await kv.list({ prefix: PROXY_KEY_PREFIX, cursor });
    const values = await Promise.all(
      page.keys.map((key) => kv.get(key.name, "json")),
    );

    for (const value of values) {
      if (value) proxies.push(value);
    }

    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return proxies.sort((left, right) => left.domain.localeCompare(right.domain));
}

function validateProxyConfig(input) {
  const domain = normalizeHostname(input.domain);
  const scheme = input.scheme === "https" ? "https" : "http";
  const targetHost = String(input.targetHost || "").trim();
  const targetPort = Number(input.targetPort || (scheme === "https" ? 443 : 80));
  const landingPath = String(input.landingPath || "").trim();
  const landingHash = String(input.landingHash || "").trim().replace(/^#/, "");

  if (!isValidHostname(domain)) {
    return { error: "代理域名格式无效" };
  }

  if (!targetHost || /[\s/]/.test(targetHost)) {
    return { error: "转发主机名或 IP 格式无效" };
  }

  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
    return { error: "转发端口必须在 1 到 65535 之间" };
  }

  const targetOrigin = createTargetOrigin(scheme, targetHost, targetPort);

  if (!targetOrigin) {
    return { error: "无法构建有效的目标地址" };
  }

  if (new URL(targetOrigin).hostname === domain) {
    return { error: "目标主机不能与代理域名相同，否则会产生循环" };
  }

  if (landingPath && !landingPath.startsWith("/")) {
    return { error: "入口路径必须以 / 开头" };
  }

  const locationResult = parseLocations(input.locationsText);

  if (locationResult.error) {
    return { error: locationResult.error };
  }

  return {
    config: {
      domain,
      scheme,
      targetHost,
      targetPort,
      landingPath,
      landingHash,
      locations: locationResult.locations,
      enabled: input.enabled !== false,
      websocket: input.websocket === true,
      forceHttps: input.forceHttps === true,
      hsts: input.hsts === true,
      blockExploits: input.blockExploits === true,
    },
  };
}

function parseLocations(value) {
  const lines = String(value || "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const locations = [];

  for (const line of lines) {
    const separator = line.indexOf("=");

    if (separator < 1) {
      return { error: `Location 格式错误：${line}` };
    }

    const path = line.slice(0, separator).trim();
    const originValue = line.slice(separator + 1).trim();

    if (!path.startsWith("/")) {
      return { error: `Location 路径必须以 / 开头：${path}` };
    }

    let origin;

    try {
      const url = new URL(originValue);

      if (
        (url.protocol !== "http:" && url.protocol !== "https:") ||
        url.username ||
        url.password ||
        url.pathname !== "/" ||
        url.search ||
        url.hash
      ) {
        return { error: `Location 目标必须是纯 HTTP(S) Origin：${originValue}` };
      }

      origin = url.origin;
    } catch {
      return { error: `Location 目标地址无效：${originValue}` };
    }

    locations.push({ path, origin });
  }

  locations.sort((left, right) => right.path.length - left.path.length);
  return { locations };
}

function createTargetOrigin(scheme, host, port) {
  try {
    const normalizedHost =
      host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
    return new URL(`${scheme}://${normalizedHost}:${port}`).origin;
  } catch {
    return null;
  }
}

function selectTargetOrigin(config, pathname) {
  const location = config.locations?.find((item) => pathname.startsWith(item.path));

  if (location) {
    return location.origin;
  }

  return createTargetOrigin(config.scheme, config.targetHost, config.targetPort);
}

function isSuspiciousPath(pathname) {
  let decodedPath;

  try {
    decodedPath = decodeURIComponent(pathname).toLowerCase();
  } catch {
    return true;
  }

  return (
    decodedPath.includes("../") ||
    decodedPath.includes("/.git") ||
    decodedPath.includes("/.svn") ||
    decodedPath.includes("/.env") ||
    decodedPath.includes("/etc/passwd") ||
    decodedPath.includes("/wp-config.php")
  );
}

function rewriteCookieDomains(sourceHeaders, responseHeaders, originHost, publicHost) {
  if (typeof sourceHeaders.getSetCookie !== "function") {
    return;
  }

  const cookies = sourceHeaders.getSetCookie();

  if (!cookies.length) {
    return;
  }

  responseHeaders.delete("Set-Cookie");

  for (const cookie of cookies) {
    const rewritten = cookie.replace(
      /;\s*Domain=([^;]+)/i,
      (match, domain) =>
        domain.replace(/^\./, "").toLowerCase() === originHost.toLowerCase()
          ? `; Domain=${publicHost}`
          : match,
    );
    responseHeaders.append("Set-Cookie", rewritten);
  }
}

async function isAuthenticated(request, env) {
  const token = getCookie(request.headers.get("Cookie"), SESSION_COOKIE);

  if (!token) {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [payloadPart, signaturePart] = parts;
  let signature;

  try {
    signature = fromBase64Url(signaturePart);
  } catch {
    return false;
  }

  const key = await importHmacKey(env.SESSION_SECRET);
  const validSignature = await crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    new TextEncoder().encode(payloadPart),
  );

  if (!validSignature) {
    return false;
  }

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(payloadPart)),
    );
    return (
      payload.username === env.ADMIN_USERNAME &&
      Number.isFinite(payload.expiresAt) &&
      payload.expiresAt > Date.now()
    );
  } catch {
    return false;
  }
}

async function createSessionToken(env) {
  const payload = toBase64Url(
    new TextEncoder().encode(
      JSON.stringify({
        username: env.ADMIN_USERNAME,
        expiresAt: Date.now() + SESSION_MAX_AGE * 1000,
        nonce: crypto.randomUUID(),
      }),
    ),
  );
  const key = await importHmacKey(env.SESSION_SECRET);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload),
  );

  return `${payload}.${toBase64Url(new Uint8Array(signature))}`;
}

async function secureEqual(actual, expected, secret) {
  const key = await importHmacKey(secret);
  const expectedSignature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(expected)),
  );

  return crypto.subtle.verify(
    "HMAC",
    key,
    expectedSignature,
    new TextEncoder().encode(String(actual)),
  );
}

function importHmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function toBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function getCookie(header, name) {
  if (!header) return "";

  for (const part of header.split(";")) {
    const separator = part.indexOf("=");

    if (separator < 0) continue;

    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }

  return "";
}

function isSameOriginRequest(request, url) {
  const fetchSite = request.headers.get("Sec-Fetch-Site");

  if (fetchSite) {
    return fetchSite === "same-origin" || fetchSite === "none";
  }

  const origin = request.headers.get("Origin");

  if (origin && origin !== "null") {
    try {
      return new URL(origin).origin === url.origin;
    } catch {
      return false;
    }
  }

  const referer = request.headers.get("Referer");

  if (referer) {
    try {
      return new URL(referer).origin === url.origin;
    } catch {
      return false;
    }
  }

  return !origin;
}

function normalizeHostname(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "");
}

function isValidHostname(value) {
  return (
    value.length <= 253 &&
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
      value,
    )
  );
}

function redirectTo(url, pathname) {
  return new Response(null, {
    status: 303,
    headers: { Location: new URL(pathname, url.origin).toString() },
  });
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function htmlResponse(html, status = 200, allowScript = false) {
  const nonce = allowScript ? crypto.randomUUID().replace(/-/g, "") : "";
  const content = allowScript ? html.replaceAll("{{NONCE}}", nonce) : html;
  const scriptPolicy = allowScript ? `'nonce-${nonce}'` : "'none'";

  return new Response(content, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": `default-src 'none'; style-src 'unsafe-inline'; script-src ${scriptPolicy}; connect-src 'self'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
    },
  });
}

function loginPage(error = "") {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Edge Proxy Manager</title>
  <style>
    :root{color-scheme:light;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#263444;background:#eef2f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at top,#f9fbfd,#e8edf4)}.card{width:min(420px,calc(100% - 32px));background:#fff;border:1px solid #dfe5ec;border-radius:16px;padding:34px;box-shadow:0 20px 60px rgba(29,43,65,.13)}.brand{display:flex;align-items:center;gap:12px;margin-bottom:28px}.logo{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#6657d9,#7ac70c);display:grid;place-items:center;color:#fff;font-weight:800}.brand h1{font-size:16px;margin:0}.brand p{margin:4px 0 0;color:#778393;font-size:13px}label{display:block;font-size:14px;font-weight:650;margin:17px 0 7px}input{width:100%;border:1px solid #cfd7e2;border-radius:9px;padding:12px 13px;font:inherit;outline:none}input:focus{border-color:#74bd13;box-shadow:0 0 0 3px rgba(116,189,19,.14)}button{width:100%;margin-top:24px;border:0;border-radius:9px;padding:12px;background:#70bd0b;color:#fff;font:inherit;font-weight:700;cursor:pointer}.error{background:#fff0f0;color:#b42318;border:1px solid #ffd1d1;border-radius:8px;padding:10px 12px;font-size:13px;margin-bottom:12px}.footer{text-align:center;color:#98a2b3;font-size:12px;margin-top:20px}
  </style>
</head>
<body>
  <main class="card">
    <div class="brand"><div class="logo">EP</div><div><h1>Edge Proxy Manager</h1><p>Cloudflare Worker 反向代理</p></div></div>
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
    <form method="post" action="/login">
      <label for="username">用户名</label>
      <input id="username" name="username" autocomplete="username" required autofocus>
      <label for="password">密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">登录</button>
    </form>
    <div class="footer">登录会话有效期 8 小时</div>
  </main>
</body>
</html>`;
}

function configurationErrorPage(message) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>配置错误</title><style>body{font-family:system-ui;background:#f4f6f8;color:#243040;padding:40px}.box{max-width:760px;margin:auto;background:white;border-radius:12px;padding:28px;box-shadow:0 10px 40px #0001}code{background:#edf1f5;padding:2px 6px;border-radius:4px}</style></head><body><main class="box"><h1>Worker 配置不完整</h1><p>${escapeHtml(message)}</p><p>请在 Worker 设置中配置环境变量、Secret 和 <code>PROXY_CONFIG</code> KV 绑定。</p></main></body></html>`;
}

function dashboardPage(username) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Edge Proxy Manager</title>
  <style>
    :root{color-scheme:light;--bg:#f5f7fb;--surface:#fff;--surface-soft:#f8fafc;--surface-hover:#f2f5f8;--text:#273247;--muted:#7c8799;--border:#e1e6ed;--shadow:0 1px 3px rgba(33,43,54,.06);--green:#6cbe08;--green-dark:#58a000;--green-soft:#eff9df;--orange:#f59f00;--blue:#1971c2;--pink:#d92d6b;--red:#d63939;--header-height:56px;--nav-height:48px;font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
    :root[data-theme="dark"]{color-scheme:dark;--bg:#151922;--surface:#1d2330;--surface-soft:#242b39;--surface-hover:#2a3242;--text:#eef2f7;--muted:#9ba6b6;--border:#313a4a;--shadow:0 12px 32px rgba(0,0,0,.24);--green-soft:#26351c}
    *{box-sizing:border-box}html{scroll-behavior:smooth}body{min-height:100vh;margin:0;background:var(--bg);color:var(--text);display:flex;flex-direction:column}button,input,select,textarea{font:inherit}button{color:inherit}[hidden]{display:none!important}.icon{width:21px;height:21px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
    .app-header{height:var(--header-height);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:center;padding:0;position:relative;z-index:40}.app-header-inner{height:100%;width:100%;max-width:1140px;padding:0 18px;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;font-size:16px;font-weight:720;letter-spacing:-.01em}.brand-logo{width:30px;height:30px;display:grid;place-items:center;clip-path:polygon(50% 0,92% 24%,92% 76%,50% 100%,8% 76%,8% 24%);background:conic-gradient(from 25deg,#ff8b00,#f13576,#7657df,#1971c2,#ff8b00);padding:3px;filter:drop-shadow(0 3px 6px rgba(90,68,181,.14))}.brand-logo span{width:100%;height:100%;display:grid;place-items:center;clip-path:inherit;background:var(--surface);color:#6f56d9;font-size:11px;font-weight:900}.header-actions{display:flex;align-items:center;gap:10px}.language{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px}.icon-button{width:40px;height:40px;border:0;border-radius:9px;background:transparent;display:grid;place-items:center;cursor:pointer;color:var(--text)}.icon-button:hover{background:var(--surface-hover)}.sun-icon{display:none}:root[data-theme="dark"] .moon-icon{display:none}:root[data-theme="dark"] .sun-icon{display:block}.account-menu{position:relative}.account-menu summary{list-style:none;display:flex;align-items:center;gap:10px;padding:5px 7px;border-radius:10px;cursor:pointer}.account-menu summary::-webkit-details-marker{display:none}.account-menu summary:hover{background:var(--surface-hover)}.avatar{width:42px;height:42px;border-radius:10px;border:1px solid var(--border);background:linear-gradient(145deg,#d8dde5,#fff);display:grid;place-items:center;color:#8b95a3;font-weight:850}.account-copy{display:flex;flex-direction:column;min-width:78px;line-height:1.25}.account-copy strong{font-size:14px}.account-copy small{font-size:12px;color:var(--muted)}.account-dropdown{position:absolute;right:0;top:56px;width:172px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:8px;box-shadow:var(--shadow);z-index:60}.account-dropdown button{width:100%;border:0;background:transparent;border-radius:7px;text-align:left;padding:10px 12px;cursor:pointer}.account-dropdown button:hover{background:var(--surface-hover)}
    .app-nav{height:var(--nav-height);background:var(--surface);border-bottom:1px solid var(--border);position:relative;z-index:30}.nav-inner{height:100%;max-width:1140px;margin:0 auto;display:flex;align-items:center;gap:2px;padding:0 18px;width:100%}.nav-link{height:var(--nav-height);border:0;background:transparent;color:var(--muted);display:flex;align-items:center;gap:7px;padding:0 12px;text-decoration:none;font-size:13px;font-weight:620;border-bottom:2px solid transparent;cursor:pointer;white-space:nowrap}.nav-link:hover,.nav-link.active,.nav-dropdown.active>.nav-link{color:var(--text);background:var(--surface-soft);border-bottom-color:var(--green)}.nav-link .chevron{width:14px;height:14px;transition:transform .18s}.nav-dropdown{height:100%;position:relative}.nav-dropdown:focus-within .chevron,.nav-dropdown:hover .chevron{transform:rotate(180deg)}.nav-menu{position:absolute;left:0;top:calc(100% - 2px);width:220px;background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:8px;box-shadow:0 16px 38px rgba(31,42,57,.15);opacity:0;visibility:hidden;transform:translateY(-6px);transition:.16s;z-index:70}.nav-dropdown:hover .nav-menu,.nav-dropdown:focus-within .nav-menu{opacity:1;visibility:visible;transform:none}.nav-menu a{display:flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;border-radius:7px;padding:11px 12px;font-size:14px}.nav-menu a:hover,.nav-menu a.active{background:var(--surface-hover);color:var(--green-dark)}
    .layout{width:100%;max-width:1140px;margin:0 auto;padding:16px 18px 28px;flex:1}.view{display:none}.view.active{display:block;animation:fadeIn .18s ease}@keyframes fadeIn{from{opacity:.5;transform:translateY(3px)}to{opacity:1;transform:none}}.view-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}.view-heading h1{font-size:16px;letter-spacing:0;margin:0 0 2px;font-weight:700}.view-heading p{margin:0;color:var(--muted);font-size:12px}.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:12px}.stat-card{min-height:0;background:var(--surface);border:1px solid var(--border);border-radius:6px;box-shadow:none;display:flex;align-items:center;gap:12px;padding:14px 16px;transition:none}.stat-card:hover{transform:none;box-shadow:none}.stat-icon{width:38px;height:38px;border-radius:6px;color:#fff;display:grid;place-items:center;flex:0 0 auto}.stat-icon.green{background:#2fb344}.stat-icon.orange{background:var(--orange)}.stat-icon.blue{background:var(--blue)}.stat-icon.red{background:var(--red)}.stat-icon .icon{width:18px;height:18px;stroke-width:2}.stat-copy{display:flex;align-items:center;gap:6px;min-width:0;flex-wrap:wrap}.stat-copy strong{font-size:15px;letter-spacing:0;font-weight:700}.stat-copy span{color:var(--text);font-size:14px;white-space:nowrap;font-weight:500}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:10px}.panel{background:var(--surface);border:1px solid var(--border);border-radius:6px;box-shadow:none;overflow:hidden}.panel-accent-green{border-top:2px solid var(--green)}.panel-accent-pink{border-top:2px solid var(--pink)}.panel-head{min-height:0;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px}.panel-head h2{font-size:15px;margin:0;font-weight:700}.panel-subtitle{font-size:12px;color:var(--muted);margin-top:1px}.help-button{width:28px;height:28px;border:1px solid var(--border);border-radius:6px;background:var(--surface);display:grid;place-items:center;color:var(--muted);cursor:pointer}.help-button:hover{background:var(--surface-hover);color:var(--text)}.recent-list{min-height:0}.recent-row{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr) 88px;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border)}.recent-row:last-child{border-bottom:0}.recent-domain{font-weight:720}.recent-target{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:left}.button{border:0;border-radius:6px;padding:8px 12px;font-weight:650;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:6px;text-decoration:none;font-size:13px}.button-primary{background:var(--green);color:#fff;box-shadow:0 4px 10px rgba(92,165,0,.2)}.button-primary:hover{background:var(--green-dark)}.button-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border)}.button-secondary:hover{background:var(--surface-hover)}.button-danger{background:transparent;color:#c92a2a;border:1px solid #f1b8b8}.button-danger:hover{background:#fff1f1}.button-sm{padding:5px 10px;font-size:12px;border-radius:6px}.button .icon{width:17px;height:17px}
    .table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:720px}th,td{text-align:left;padding:11px 16px;border-bottom:1px solid var(--border);font-size:13px}th{background:var(--surface-soft);color:var(--muted);font-size:12px;font-weight:750;text-transform:uppercase;letter-spacing:.045em}tbody tr:hover{background:var(--surface-soft)}tbody tr:last-child td{border-bottom:0}.domain-cell{display:flex;align-items:center;gap:11px}.domain-dot{width:9px;height:9px;border-radius:50%;background:#adb5bd;box-shadow:0 0 0 4px rgba(173,181,189,.15)}.domain-dot.enabled{background:#2fb344;box-shadow:0 0 0 4px rgba(47,179,68,.13)}.domain-name{font-weight:750}.domain-link{color:var(--blue);text-decoration:none}.domain-link:hover{text-decoration:underline}.recent-domain.domain-link{font-weight:720}.quick-url-field{margin-bottom:12px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--surface-soft)}.quick-url-field > label{margin-bottom:6px}.quick-url-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}.quick-url-row input{width:100%;min-height:38px}.quick-url-field .hint{margin-top:6px}.target{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);font-size:12px}.badge{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:650;min-width:52px}.badge.on{background:#e9f8d6;color:#477c00}.badge.off{background:#edf0f4;color:#697586}.actions{display:flex;gap:8px}.empty-state{min-height:0;padding:40px 16px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}.empty-icon{width:44px;height:44px;border-radius:12px;background:var(--green-soft);color:var(--green-dark);display:grid;place-items:center;margin-bottom:10px}.empty-icon .icon{width:22px;height:22px}.empty-state h2{font-size:16px;margin:0 0 4px}.empty-state p{color:var(--muted);font-size:12px;margin:0 0 14px}.compact-empty{min-height:0;padding:28px 16px}.managed-state{min-height:0;padding:40px 16px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}.managed-state .empty-icon{background:#fff0f6;color:var(--pink)}.managed-state h2{font-size:22px;margin:0 0 8px}.managed-state p{max-width:620px;color:var(--muted);line-height:1.7;margin:0}.managed-tags{display:flex;gap:9px;flex-wrap:wrap;justify-content:center;margin-top:22px}.managed-tag{background:var(--surface-soft);border:1px solid var(--border);border-radius:999px;padding:7px 11px;color:var(--muted);font-size:12px}.settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.setting-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:24px;box-shadow:0 3px 12px rgba(32,43,58,.04)}.setting-card .setting-icon{width:44px;height:44px;border-radius:10px;background:var(--surface-soft);display:grid;place-items:center;color:var(--green-dark);margin-bottom:18px}.setting-card h2{font-size:17px;margin:0 0 8px}.setting-card p{font-size:13px;color:var(--muted);line-height:1.7;margin:0}.page-footer{min-height:44px;background:var(--surface);border-top:1px solid var(--border);display:flex;align-items:center;justify-content:center;padding:0;color:var(--muted);font-size:12px}.page-footer-inner{width:100%;max-width:1140px;padding:0 18px;display:flex;align-items:center;justify-content:space-between;gap:12px}
    dialog{width:min(760px,calc(100% - 24px));max-height:calc(100vh - 28px);border:0;border-radius:10px;padding:0;background:var(--surface);color:var(--text);box-shadow:0 20px 70px rgba(17,24,39,.28)}dialog::backdrop{background:rgba(23,31,43,.66);backdrop-filter:blur(2px)}.modal-form{display:flex;flex-direction:column;max-height:calc(100vh - 36px)}.modal-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}.modal-title{display:flex;align-items:center;gap:12px}.modal-title-mark{width:36px;height:36px;border-radius:9px;background:var(--green-soft);color:var(--green-dark);display:grid;place-items:center}.modal-head h2{margin:0;font-size:20px}.close-button{width:38px;height:38px;border:0;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer;display:grid;place-items:center}.close-button:hover{background:var(--surface-hover);color:var(--text)}.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 22px}.tab{border:0;background:transparent;padding:15px 17px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}.tab.active{color:var(--text);border-bottom-color:var(--green);font-weight:750}.modal-body{overflow:auto}.tab-panel{display:none;padding:14px 16px}.tab-panel.active{display:block}.grid{display:grid;grid-template-columns:1fr 1.5fr .7fr;gap:15px}.field{margin-bottom:12px}.field label{display:block;font-size:13px;font-weight:750;margin-bottom:7px}.field input,.field select,.field textarea{width:100%;border:1px solid var(--border);border-radius:8px;padding:11px 12px;outline:none;background:var(--surface);color:var(--text)}.field textarea{min-height:170px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--green);box-shadow:0 0 0 3px rgba(108,190,8,.14)}.hint{color:var(--muted);font-size:12px;margin-top:6px;line-height:1.6}.switches{display:grid;grid-template-columns:1fr 1fr;gap:12px}.switch{display:flex;align-items:center;justify-content:space-between;border:1px solid var(--border);border-radius:9px;padding:13px 14px;background:var(--surface-soft)}.switch input{width:19px;height:19px;accent-color:var(--green)}.info{background:#eff6ff;border:1px solid #cfe1ff;color:#385777;border-radius:9px;padding:14px;font-size:13px;line-height:1.7}:root[data-theme="dark"] .info{background:#202d42;border-color:#31476a;color:#b7cef3}.modal-foot{display:flex;justify-content:space-between;padding:12px 16px;border-top:1px solid var(--border);background:var(--surface-soft)}.toast{position:fixed;right:24px;bottom:24px;background:#263444;color:#fff;padding:12px 16px;border-radius:9px;opacity:0;transform:translateY(12px);pointer-events:none;transition:.2s;z-index:100}.toast.show{opacity:1;transform:none}.toast.error{background:#b42318}
    @media(max-width:1100px){.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.dashboard-grid{grid-template-columns:1fr}.settings-grid{grid-template-columns:1fr 1fr}}@media(max-width:760px){:root{--header-height:52px;--nav-height:46px}.app-header-inner{padding:0 12px}.brand{font-size:15px}.brand-logo{width:28px;height:28px}.language,.account-copy{display:none}.nav-inner{padding:0 12px;overflow:visible}.nav-link{padding:0 12px}.nav-link span{display:none}.layout{padding:14px 12px 28px}.view-heading{align-items:stretch;flex-direction:column}.summary{grid-template-columns:1fr;gap:12px}.stat-card{min-height:0}.settings-grid{grid-template-columns:1fr}.panel-head{padding:17px 18px}.recent-row{grid-template-columns:1fr}.recent-target{display:none}.page-footer{padding:17px 16px;align-items:flex-start;flex-direction:column}.grid{grid-template-columns:1fr}.switches{grid-template-columns:1fr}.tab-panel{padding:20px 18px}.modal-foot{padding:15px 18px}.nav-menu{left:-58px}}
  </style>
</head>
<body>
  <header class="app-header"><div class="app-header-inner">
      <a class="brand" href="#dashboard" data-view-link="dashboard"><span class="brand-logo"><span>EP</span></span><span>Edge Proxy Manager</span></a>
    <div class="header-actions">
      <span class="language">🇨🇳 <span>中文</span></span>
      <button class="icon-button" type="button" id="themeToggle" aria-label="切换深色模式">
        <svg class="icon moon-icon" viewBox="0 0 24 24"><path d="M20.5 14.3A8.5 8.5 0 0 1 9.7 3.5 8.5 8.5 0 1 0 20.5 14.3Z"/></svg>
        <svg class="icon sun-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
      </button>
      <details class="account-menu">
        <summary><span class="avatar">EP</span><span class="account-copy"><strong>${escapeHtml(username)}</strong><small>管理员</small></span></summary>
        <div class="account-dropdown"><form method="post" action="/logout"><button type="submit">退出登录</button></form></div>
      </details>
    </div>
    </div></header>
  <nav class="app-nav" aria-label="主导航">
    <div class="nav-inner">
      <a class="nav-link active" href="#dashboard" data-view-link="dashboard"><svg class="icon" viewBox="0 0 24 24"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v10h13V10M9.5 20v-6h5v6"/></svg><span>仪表板</span></a>
      <div class="nav-dropdown" id="hostNav">
        <button class="nav-link" type="button"><svg class="icon" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg><span>主机列表</span><svg class="icon chevron" viewBox="0 0 24 24"><path d="m7 10 5 5 5-5"/></svg></button>
        <div class="nav-menu"><a href="#proxies" data-view-link="proxies"><svg class="icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/><circle cx="5" cy="12" r="2"/></svg>代理服务列表</a></div>
      </div>
      <a class="nav-link" href="#certificates" data-view-link="certificates"><svg class="icon" viewBox="0 0 24 24"><path d="M12 3 20 7v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4Z"/><path d="m9 12 2 2 4-4"/></svg><span>证书状态</span></a>
      <a class="nav-link" href="#settings" data-view-link="settings"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/></svg><span>设置</span></a>
    </div>
  </nav>
  <main class="layout">
    <section class="view active" data-view="dashboard">
      <div class="view-heading"><div><h1>仪表板</h1></div></div>
      <div class="summary">
        <article class="stat-card"><span class="stat-icon green"><svg class="icon" viewBox="0 0 24 24"><path d="m13 2-8 12h7l-1 8 8-12h-7l1-8Z"/></svg></span><div class="stat-copy"><strong id="totalCount">0</strong><span>个代理服务</span></div></article>
        <article class="stat-card"><span class="stat-icon orange"><svg class="icon" viewBox="0 0 24 24"><path d="M5 19 19 5M9 5h10v10"/><path d="M5 9v10h10"/></svg></span><div class="stat-copy"><strong id="enabledCount">0</strong><span>个正在运行</span></div></article>
        <article class="stat-card"><span class="stat-icon blue"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7M10.5 13.5a2 2 0 0 1 0-3M13.5 10.5a2 2 0 0 1 0 3"/></svg></span><div class="stat-copy"><strong id="websocketCount">0</strong><span>个 WebSocket</span></div></article>
        <article class="stat-card"><span class="stat-icon red"><svg class="icon" viewBox="0 0 24 24"><path d="M5 7h8a4 4 0 0 1 4 4v6M9 3 5 7l4 4"/><path d="M19 17h-8a4 4 0 0 1-4-4V7M15 21l4-4-4-4"/></svg></span><div class="stat-copy"><strong id="locationCount">0</strong><span>个自定义路径</span></div></article>
      </div>
      <div class="dashboard-grid">
        <section class="panel panel-accent-green"><div class="panel-head"><div><h2>最近代理服务</h2></div><a class="button button-secondary button-sm" href="#proxies" data-view-link="proxies">查看全部</a></div><div class="recent-list" id="recentProxies"></div></section>
      </div>
    </section>
    <section class="view" data-view="proxies">
      <div class="view-heading"><div><h1>代理服务列表</h1></div><button class="button button-primary open-editor" id="headerAddProxy" type="button" hidden><svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>添加代理服务</button></div>
      <section class="panel panel-accent-green">
        <div class="panel-head" id="proxyPanelHead" hidden><div><h2>主机列表</h2><div class="panel-subtitle">Cloudflare Worker 反向代理主机</div></div><button class="help-button" type="button" title="代理域名需要绑定到此 Worker"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.8 9a2.4 2.4 0 1 1 3.3 2.2c-.8.4-1.1.9-1.1 1.8M12 17h.01"/></svg></button></div>
        <div class="table-wrap" id="proxyTableWrap" hidden><table><thead><tr><th>域名</th><th>转发目标</th><th>状态</th><th>WebSocket</th><th>更新时间</th><th>操作</th></tr></thead><tbody id="proxyRows"></tbody></table></div>
        <div class="empty-state" id="emptyState"><span class="empty-icon"><svg class="icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/><circle cx="5" cy="12" r="2"/></svg></span><h2>没有代理服务</h2><p>创建第一条配置，让 Cloudflare Worker 开始反向代理。</p><button class="button button-primary open-editor" type="button"><svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>添加代理服务</button></div>
      </section>
    </section>
    <section class="view" data-view="certificates">
      <div class="view-heading"><div><h1>证书状态</h1></div></div>
      <section class="panel panel-accent-pink"><div class="panel-head"><div><h2>Cloudflare 托管证书</h2><div class="panel-subtitle">无需在源站安装 HTTPS 证书</div></div><button class="help-button" type="button" title="Worker 到 HTTP 源站的连接不使用访客证书"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.8 9a2.4 2.4 0 1 1 3.3 2.2c-.8.4-1.1.9-1.1 1.8M12 17h.01"/></svg></button></div><div class="managed-state"><span class="empty-icon"><svg class="icon" viewBox="0 0 24 24"><path d="M12 3 20 7v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4Z"/><path d="m9 12 2 2 4-4"/></svg></span><h2>证书已交由 Cloudflare 管理</h2><p>Custom Domain 会自动提供 HTTPS、处理证书签发与续期。代理目标仍可使用 HTTP，例如公网源站的 80 或自定义端口。</p><div class="managed-tags"><span class="managed-tag">自动签发</span><span class="managed-tag">自动续期</span><span class="managed-tag">TLS 边缘终止</span><span class="managed-tag">HTTP 回源支持</span></div></div></section>
    </section>
    <section class="view" data-view="settings">
      <div class="view-heading"><div><h1>设置</h1></div></div>
      <div class="settings-grid">
        <article class="setting-card"><span class="setting-icon"><svg class="icon" viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h10"/></svg></span><h2>配置存储</h2><p>代理规则保存在 Cloudflare KV，通过 PROXY_CONFIG 绑定读取和更新。</p></article>
        <article class="setting-card"><span class="setting-icon"><svg class="icon" viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></span><h2>管理会话</h2><p>登录状态使用签名 Cookie 保存，会话有效期为 8 小时并启用 Secure 与 SameSite。</p></article>
        <article class="setting-card"><span class="setting-icon"><svg class="icon" viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 15-4M20 12a8 8 0 0 1-15 4"/><path d="m19 4 .2 4-4-.2M5 20l-.2-4 4 .2"/></svg></span><h2>回源能力</h2><p>支持 HTTP、HTTPS、WebSocket、重定向改写、Cookie 域名改写和自定义 Locations。</p></article>
      </div>
    </section>
  </main>
  <footer class="page-footer"><div class="page-footer-inner"><span>© 2026 Edge Proxy Manager</span><span class="build-id">build open-source</span><span>Powered by Cloudflare Workers · HTTPS 证书自动管理</span></div></footer>
  <dialog id="editor">
    <form id="proxyForm" class="modal-form">
      <div class="modal-head"><div class="modal-title"><span class="modal-title-mark"><svg class="icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/><circle cx="5" cy="12" r="2"/></svg></span><h2 id="dialogTitle">添加代理服务</h2></div><button type="button" class="close-button" id="closeDialog" aria-label="关闭"><svg class="icon" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
      <div class="tabs"><button type="button" class="tab active" data-tab="details">详情</button><button type="button" class="tab" data-tab="locations">自定义路径</button><button type="button" class="tab" data-tab="ssl">SSL</button></div>
      <div class="modal-body">
        <section class="tab-panel active" data-panel="details"><input type="hidden" id="originalDomain"><div class="field"><label for="domain">代理域名</label><input id="domain" placeholder="api.example.com" required><div class="hint">该域名还需要在 Cloudflare 中绑定到当前 Worker。</div></div><div class="field quick-url-field"><label for="originUrl">快速粘贴源站链接</label><div class="quick-url-row"><input id="originUrl" placeholder="http://origin.example.com:8080/management.html#/" autocomplete="off"><button type="button" class="button button-secondary button-sm" id="parseOriginUrl">解析填入</button></div><div class="hint">粘贴完整源站 URL，自动填入下方协议 / 主机 / 端口 / 路径 / Hash。</div></div><div class="grid"><div class="field"><label for="scheme">回源协议</label><select id="scheme"><option value="http">HTTP</option><option value="https">HTTPS</option></select></div><div class="field"><label for="targetHost">公网源站主机名 / IP</label><input id="targetHost" placeholder="origin.example.com" required></div><div class="field"><label for="targetPort">端口</label><input id="targetPort" type="number" min="1" max="65535" value="80" required></div></div><div class="grid"><div class="field"><label for="landingPath">默认入口路径</label><input id="landingPath" placeholder="/management.html"></div><div class="field"><label for="landingHash">入口 Hash</label><input id="landingHash" placeholder="/"><div class="hint">填写 / 将生成 #/</div></div><div class="field"></div></div><div class="switches"><label class="switch"><span>启用代理</span><input id="enabled" type="checkbox" checked></label><label class="switch"><span>WebSocket 支持</span><input id="websocket" type="checkbox"></label><label class="switch"><span>阻止常见攻击</span><input id="blockExploits" type="checkbox" checked></label></div></section>
        <section class="tab-panel" data-panel="locations"><div class="field"><label for="locationsText">自定义路径规则</label><textarea id="locationsText" placeholder="/api = http://api.example.com:8080&#10;/assets = https://static.example.com:443"></textarea><div class="hint">每行一条，格式：路径 = http(s)://主机:端口。匹配时优先使用最长路径。</div></div></section>
        <section class="tab-panel" data-panel="ssl"><div class="info">访问者证书由 Cloudflare Custom Domain 自动管理。这里的回源协议决定 Worker 使用 HTTP 还是 HTTPS 连接目标源站。</div><div class="switches" style="margin-top:16px"><label class="switch"><span>强制 HTTPS</span><input id="forceHttps" type="checkbox" checked></label><label class="switch"><span>启用 HSTS</span><input id="hsts" type="checkbox"></label></div></section>
      </div>
      <div class="modal-foot"><button type="button" class="button button-secondary" id="cancelDialog">取消</button><button type="submit" class="button button-primary">保存代理服务</button></div>
    </form>
  </dialog>
  <div class="toast" id="toast"></div>
  <script nonce="{{NONCE}}">
    const state = { proxies: [] };
    const editor = document.getElementById("editor");
    const form = document.getElementById("proxyForm");
    const fields = Object.fromEntries([
      "originalDomain","originUrl","domain","scheme","targetHost","targetPort","landingPath","landingHash","locationsText","enabled","websocket","blockExploits","forceHttps","hsts"
    ].map(id => [id, document.getElementById(id)]));

    function showToast(message, error = false) {
      const toast = document.getElementById("toast");
      toast.textContent = message;
      toast.className = "toast show" + (error ? " error" : "");
      setTimeout(() => toast.className = "toast", 2800);
    }

    async function requestJson(path, options = {}) {
      const response = await fetch(path, options);
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "请求失败 (" + response.status + ")");
      return data;
    }

    function currentView() {
      const value = location.hash.replace(/^#/, "");
      return ["dashboard", "proxies", "certificates", "settings"].includes(value) ? value : "dashboard";
    }

    function showView(name) {
      document.querySelectorAll(".view").forEach(view => view.classList.toggle("active", view.dataset.view === name));
      document.querySelectorAll("[data-view-link]").forEach(link => link.classList.toggle("active", link.dataset.viewLink === name));
      document.getElementById("hostNav").classList.toggle("active", name === "proxies");
      document.querySelectorAll(".account-menu[open]").forEach(menu => menu.removeAttribute("open"));
    }

    function setTheme(theme) {
      document.documentElement.dataset.theme = theme;
      document.getElementById("themeToggle").setAttribute("aria-label", theme === "dark" ? "切换浅色模式" : "切换深色模式");
      localStorage.setItem("edge-proxy-theme", theme);
    }

    function formatLocations(config) {
      return (config.locations || []).map(item => item.path + " = " + item.origin).join("\\n");
    }

    function closeEditor() {
      if (typeof editor.close === "function") editor.close();
      else editor.removeAttribute("open");
    }

    
    function normalizeLandingHash(hash) {
      if (!hash) return "";
      return hash.startsWith("#") ? hash.slice(1) : hash;
    }

    function parseOriginUrl(raw, options = {}) {
      const value = String(raw || "").trim();
      if (!value) {
        if (!options.silent) showToast("请先粘贴源站链接", true);
        return null;
      }
      let parsed;
      try {
        parsed = new URL(value.includes("://") ? value : ("http://" + value));
      } catch {
        if (!options.silent) showToast("链接格式无效", true);
        return null;
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        if (!options.silent) showToast("仅支持 http 或 https 链接", true);
        return null;
      }
      const scheme = parsed.protocol.replace(":", "");
      const defaultPort = scheme === "https" ? "443" : "80";
      const port = parsed.port || defaultPort;
      const landingPath = parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "";
      const landingHash = normalizeLandingHash(parsed.hash);
      fields.scheme.value = scheme;
      fields.targetHost.value = parsed.hostname;
      fields.targetPort.value = port;
      fields.landingPath.value = landingPath;
      fields.landingHash.value = landingHash;
      fields.originUrl.value = parsed.origin + (landingPath || "") + (parsed.search || "") + (parsed.hash || "");
      if (!options.silent) {
        const parts = [scheme.toUpperCase(), parsed.hostname + ":" + port];
        if (landingPath) parts.push(landingPath);
        if (landingHash) parts.push("#" + landingHash);
        showToast("已解析：" + parts.join(" · "));
      }
      return true;
    }

function openEditor(config = null) {
      form.reset();
      fields.originUrl.value = "";
      fields.enabled.checked = true;
      fields.blockExploits.checked = true;
      fields.forceHttps.checked = true;
      fields.scheme.value = "http";
      fields.targetPort.value = "80";
      fields.originalDomain.value = config?.domain || "";
      fields.domain.value = config?.domain || "";
      fields.scheme.value = config?.scheme || "http";
      fields.targetHost.value = config?.targetHost || "";
      fields.targetPort.value = config?.targetPort || (fields.scheme.value === "https" ? 443 : 80);
      fields.landingPath.value = config?.landingPath || "";
      fields.landingHash.value = config?.landingHash || "";
      if (config?.targetHost) {
        const port = config.targetPort || (config.scheme === "https" ? 443 : 80);
        const path = config.landingPath || "";
        const hash = config.landingHash ? ("#" + String(config.landingHash).replace(/^#/, "")) : "";
        fields.originUrl.value = (config.scheme || "http") + "://" + config.targetHost + ":" + port + path + hash;
      }
      fields.locationsText.value = config ? formatLocations(config) : "";
      fields.enabled.checked = config ? config.enabled : true;
      fields.websocket.checked = config?.websocket || false;
      fields.blockExploits.checked = config ? config.blockExploits : true;
      fields.forceHttps.checked = config ? config.forceHttps : true;
      fields.hsts.checked = config?.hsts || false;
      document.getElementById("dialogTitle").textContent = config ? "编辑代理服务" : "添加代理服务";
      selectTab("details");
      if (typeof editor.showModal === "function") editor.showModal();
      else editor.setAttribute("open", "");
    }

    function selectTab(name) {
      document.querySelectorAll(".tab").forEach(tab => tab.classList.toggle("active", tab.dataset.tab === name));
      document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.toggle("active", panel.dataset.panel === name));
    }

    function createStatusBadge(enabled) {
      const badge = document.createElement("span");
      badge.className = "badge " + (enabled ? "on" : "off");
      badge.textContent = enabled ? "运行中" : "已停用";
      return badge;
    }

    function renderRecent() {
      const recent = document.getElementById("recentProxies");
      recent.replaceChildren();
      const items = [...state.proxies].sort((left, right) => String(right.updatedAt || "").localeCompare(String(left.updatedAt || ""))).slice(0, 5);

      if (!items.length) {
        const empty = document.createElement("div");
        empty.className = "empty-state compact-empty";
        const title = document.createElement("h2");
        title.textContent = "暂无代理服务";
        const description = document.createElement("p");
        description.textContent = "创建第一条配置后会显示在这里。";
        const button = document.createElement("button");
        button.className = "button button-primary";
        button.type = "button";
        button.textContent = "添加代理服务";
        button.addEventListener("click", () => openEditor());
        empty.append(title, description, button);
        recent.append(empty);
        return;
      }

      for (const config of items) {
        const row = document.createElement("div");
        row.className = "recent-row";
        const domain = document.createElement("a");
        domain.className = "recent-domain domain-link";
        domain.href = "https://" + config.domain;
        domain.target = "_blank";
        domain.rel = "noopener noreferrer";
        domain.textContent = "https://" + config.domain;
        domain.title = "在新窗口打开 https://" + config.domain;
        const target = document.createElement("span");
        target.className = "recent-target";
        target.textContent = config.scheme + "://" + config.targetHost + ":" + config.targetPort;
        row.append(domain, target, createStatusBadge(config.enabled));
        recent.append(row);
      }
    }

    function render() {
      const rows = document.getElementById("proxyRows");
      const hasProxies = state.proxies.length > 0;
      rows.replaceChildren();
      document.getElementById("emptyState").hidden = hasProxies;
      document.getElementById("proxyTableWrap").hidden = !hasProxies;
      document.getElementById("proxyPanelHead").hidden = !hasProxies;
      document.getElementById("headerAddProxy").hidden = !hasProxies;
      document.getElementById("totalCount").textContent = state.proxies.length;
      document.getElementById("enabledCount").textContent = state.proxies.filter(item => item.enabled).length;
      document.getElementById("websocketCount").textContent = state.proxies.filter(item => item.websocket).length;
      document.getElementById("locationCount").textContent = state.proxies.reduce((sum, item) => sum + (item.locations?.length || 0), 0);

      for (const config of state.proxies) {
        const row = document.createElement("tr");
        const domain = document.createElement("td");
        const domainWrap = document.createElement("div");
        domainWrap.className = "domain-cell";
        const dot = document.createElement("span");
        dot.className = "domain-dot" + (config.enabled ? " enabled" : "");
        const domainName = document.createElement("a");
        domainName.className = "domain-name domain-link";
        domainName.href = "https://" + config.domain;
        domainName.target = "_blank";
        domainName.rel = "noopener noreferrer";
        domainName.textContent = "https://" + config.domain;
        domainName.title = "在新窗口打开 https://" + config.domain;
        domainWrap.append(dot, domainName);
        domain.append(domainWrap);
        const target = document.createElement("td");
        target.className = "target";
        target.textContent = config.scheme + "://" + config.targetHost + ":" + config.targetPort;
        const status = document.createElement("td");
        status.append(createStatusBadge(config.enabled));
        const websocket = document.createElement("td");
        websocket.textContent = config.websocket ? "已启用" : "未启用";
        const updated = document.createElement("td");
        updated.textContent = config.updatedAt ? new Date(config.updatedAt).toLocaleString() : "-";
        const actions = document.createElement("td");
        actions.className = "actions";
        const editButton = document.createElement("button");
        editButton.className = "button button-secondary button-sm";
        editButton.type = "button";
        editButton.textContent = "编辑";
        editButton.addEventListener("click", () => openEditor(config));
        const deleteButton = document.createElement("button");
        deleteButton.className = "button button-danger button-sm";
        deleteButton.type = "button";
        deleteButton.textContent = "删除";
        deleteButton.addEventListener("click", () => removeProxy(config.domain));
        actions.append(editButton, deleteButton);
        row.append(domain, target, status, websocket, updated, actions);
        rows.append(row);
      }

      renderRecent();
    }

    async function loadProxies() {
      try {
        const data = await requestJson("/api/proxies");
        state.proxies = data.proxies;
        render();
      } catch (error) {
        showToast(error.message, true);
      }
    }

    async function removeProxy(domain) {
      if (!confirm("确定删除 " + domain + "？")) return;
      try {
        await requestJson("/api/proxies/" + encodeURIComponent(domain), { method: "DELETE" });
        showToast("代理配置已删除");
        await loadProxies();
      } catch (error) {
        showToast(error.message, true);
      }
    }

    document.getElementById("parseOriginUrl").addEventListener("click", () => parseOriginUrl(fields.originUrl.value));
    fields.originUrl.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        parseOriginUrl(fields.originUrl.value);
      }
    });
    fields.originUrl.addEventListener("paste", () => {
      setTimeout(() => parseOriginUrl(fields.originUrl.value, { silent: true }), 0);
    });
    document.querySelectorAll(".open-editor").forEach(button => button.addEventListener("click", () => openEditor()));
    document.getElementById("closeDialog").addEventListener("click", closeEditor);
    document.getElementById("cancelDialog").addEventListener("click", closeEditor);
    document.querySelectorAll(".tab").forEach(tab => tab.addEventListener("click", () => selectTab(tab.dataset.tab)));
    document.getElementById("themeToggle").addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
    window.addEventListener("hashchange", () => showView(currentView()));
    fields.scheme.addEventListener("change", () => {
      if (fields.targetPort.value === "80" || fields.targetPort.value === "443") fields.targetPort.value = fields.scheme.value === "https" ? "443" : "80";
    });
    editor.addEventListener("click", event => {
      if (event.target === editor) closeEditor();
    });

    form.addEventListener("submit", async event => {
      event.preventDefault();
      const payload = {
        originalDomain: fields.originalDomain.value,
        domain: fields.domain.value,
        scheme: fields.scheme.value,
        targetHost: fields.targetHost.value,
        targetPort: Number(fields.targetPort.value),
        landingPath: fields.landingPath.value,
        landingHash: fields.landingHash.value,
        locationsText: fields.locationsText.value,
        enabled: fields.enabled.checked,
        websocket: fields.websocket.checked,
        blockExploits: fields.blockExploits.checked,
        forceHttps: fields.forceHttps.checked,
        hsts: fields.hsts.checked,
      };

      try {
        await requestJson("/api/proxies", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        closeEditor();
        showToast("代理配置已保存");
        location.hash = "proxies";
        showView("proxies");
        await loadProxies();
      } catch (error) {
        showToast(error.message, true);
      }
    });

    const savedTheme = localStorage.getItem("edge-proxy-theme");
    if (savedTheme === "dark" || savedTheme === "light") setTheme(savedTheme);
    else if (matchMedia("(prefers-color-scheme: dark)").matches) setTheme("dark");
    showView(currentView());
    loadProxies();
  </script>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
