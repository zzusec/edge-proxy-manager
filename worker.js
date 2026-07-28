const PROXY_KEY_PREFIX = "proxy:";
const CF_SETTINGS_KEY = "settings:cloudflare";
const ADMIN_SETTINGS_KEY = "settings:admin";
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
    const usernameMatches = await secureEqual(
      username,
      env.ADMIN_USERNAME,
      env.SESSION_SECRET,
    );
    const passwordMatches = await verifyAdminPassword(env, password);

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

    const cfSettings = await getCloudflareSettings(env.PROXY_CONFIG);
    if (!(cfSettings?.tokens || []).length) {
      return jsonResponse(
        { error: "请先绑定 Cloudflare API 令牌" },
        403,
      );
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

    try {
      const zones = await listZonesFromAllTokens(cfSettings);
      const domain = validation.config.domain;
      const matchedZone = findZoneForHostname(domain, zones);
      if (!matchedZone) {
        return jsonResponse(
          {
            error:
              "域名未在当前 Cloudflare 账号托管",
          },
          400,
        );
      }

      // Auto-bind domain to Worker
      const token = cfSettings.tokens.find(t => t.id === matchedZone.tokenId);
      if (token) {
        try {
          await ensureWorkerRoute(token.apiToken, matchedZone.id, domain, matchedZone.name, "edge-proxy-manager");
        } catch (routeError) {
          console.error("Failed to bind domain:", routeError);
          // Continue anyway - user can manually bind
        }
      }
    } catch (error) {
      return jsonResponse(
        {
          error:
            "域名校验失败：" +
            (error instanceof Error ? error.message : "请重新绑定 API 令牌"),
        },
        502,
      );
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

  if (url.pathname === "/api/settings/cloudflare" && request.method === "GET") {
    const settings = await getCloudflareSettings(env.PROXY_CONFIG);
    return jsonResponse(publicCloudflareSettings(settings));
  }

  if (url.pathname === "/api/settings/cloudflare" && request.method === "POST") {
    if (!isSameOriginRequest(request, url)) {
      return jsonResponse({ error: "Forbidden" }, 403);
    }

    let input;
    try {
      input = await request.json();
    } catch {
      return jsonResponse({ error: "请求数据不是有效 JSON" }, 400);
    }

    const apiToken = String(input.apiToken || "").trim();
    const tokenName = String(input.name || "").trim();
    if (!apiToken || apiToken.length < 20) {
      return jsonResponse({ error: "请填写有效的 API 令牌" }, 400);
    }

    try {
      const verified = await verifyCloudflareToken(apiToken);
      const zones = await listCloudflareZones(apiToken);
      const settings = await getCloudflareSettings(env.PROXY_CONFIG);
      // dedupe by exact token value
      if (settings.tokens.some((item) => item.apiToken === apiToken)) {
        return jsonResponse({ error: "该令牌已添加" }, 400);
      }
      const entry = {
        id: cryptoRandomId(),
        name: tokenName || verified.accountName || `令牌 ${settings.tokens.length + 1}`,
        apiToken,
        accountName: verified.accountName || "",
        verifiedAt: new Date().toISOString(),
        zoneCount: zones.length,
      };
      settings.tokens.push(entry);
      await env.PROXY_CONFIG.put(CF_SETTINGS_KEY, JSON.stringify(settings));
      const allZones = await listZonesFromAllTokens(settings);
      // persist refreshed zone counts
      await env.PROXY_CONFIG.put(CF_SETTINGS_KEY, JSON.stringify(settings));
      return jsonResponse({
        ...publicCloudflareSettings(settings),
        zones: allZones.map((z) => ({
          id: z.id,
          name: z.name,
          status: z.status,
          tokenId: z.tokenId,
          tokenName: z.tokenName,
        })),
      });
    } catch (error) {
      return jsonResponse(
        { error: error instanceof Error ? error.message : "Cloudflare API 验证失败" },
        400,
      );
    }
  }

  if (url.pathname === "/api/settings/cloudflare" && request.method === "DELETE") {
    if (!isSameOriginRequest(request, url)) {
      return jsonResponse({ error: "Forbidden" }, 403);
    }

    let tokenId = url.searchParams.get("id") || "";
    if (!tokenId) {
      try {
        const body = await request.clone().json();
        tokenId = String(body?.id || "");
      } catch {
        tokenId = "";
      }
    }

    if (!tokenId) {
      await env.PROXY_CONFIG.delete(CF_SETTINGS_KEY);
      return jsonResponse({ configured: false, tokens: [], tokenCount: 0 });
    }

    const settings = await getCloudflareSettings(env.PROXY_CONFIG);
    settings.tokens = (settings.tokens || []).filter((item) => item.id !== tokenId);
    if (!settings.tokens.length) {
      await env.PROXY_CONFIG.delete(CF_SETTINGS_KEY);
      return jsonResponse({ configured: false, tokens: [], tokenCount: 0 });
    }
    await env.PROXY_CONFIG.put(CF_SETTINGS_KEY, JSON.stringify(settings));
    return jsonResponse(publicCloudflareSettings(settings));
  }

  if (url.pathname === "/api/account/password" && request.method === "POST") {
    if (!isSameOriginRequest(request, url)) {
      return jsonResponse({ error: "Forbidden" }, 403);
    }

    let input;
    try {
      input = await request.json();
    } catch {
      return jsonResponse({ error: "请求数据不是有效 JSON" }, 400);
    }

    const currentPassword = String(input.currentPassword || "");
    const newPassword = String(input.newPassword || "");
    const confirmPassword = String(input.confirmPassword || "");

    if (!(await verifyAdminPassword(env, currentPassword))) {
      return jsonResponse({ error: "当前密码不正确" }, 400);
    }
    if (newPassword.length < 8) {
      return jsonResponse({ error: "新密码至少 8 位" }, 400);
    }
    if (newPassword !== confirmPassword) {
      return jsonResponse({ error: "两次输入的新密码不一致" }, 400);
    }
    if (newPassword === currentPassword) {
      return jsonResponse({ error: "新密码不能与当前密码相同" }, 400);
    }

    const passwordHash = await hashAdminPassword(newPassword, env.SESSION_SECRET);
    await env.PROXY_CONFIG.put(
      ADMIN_SETTINGS_KEY,
      JSON.stringify({
        passwordHash,
        updatedAt: new Date().toISOString(),
      }),
    );

    return jsonResponse({ ok: true, updatedAt: new Date().toISOString() });
  }

  if (url.pathname === "/api/certificates" && request.method === "GET") {
    const proxies = await listProxyConfigs(env.PROXY_CONFIG);
    const settings = await getCloudflareSettings(env.PROXY_CONFIG);
    const hasTokens = (settings?.tokens || []).length > 0;

    if (!hasTokens) {
      return jsonResponse({
        configured: false,
        certificates: proxies.map((proxy) => ({
          domain: proxy.domain,
          enabled: proxy.enabled !== false,
          origin: createTargetOrigin(proxy.scheme, proxy.targetHost, proxy.targetPort),
          forceHttps: Boolean(proxy.forceHttps),
          hsts: Boolean(proxy.hsts),
          zone: null,
          status: "unknown",
          statusText: "未绑定 API",
          sslMode: null,
          hosts: [],
          expiresOn: null,
          daysLeft: null,
          autoRenew: null,
          issuer: null,
          type: null,
        })),
      });
    }

    try {
      const zones = await listZonesFromAllTokens(settings);
      await env.PROXY_CONFIG.put(CF_SETTINGS_KEY, JSON.stringify(settings));
      const zoneSslCache = new Map();
      const certificates = [];

      for (const proxy of proxies) {
        const zone = findZoneForHostname(proxy.domain, zones);
        let sslMode = null;
        let packs = [];
        let status = "pending";
        let statusText = "待确认";
        let expiresOn = null;
        let daysLeft = null;
        let autoRenew = null;
        let issuer = null;
        let certType = null;
        let hosts = proxy.domain ? [proxy.domain] : [];

        if (!zone) {
          status = "unmanaged";
          statusText = "域名未托管";
        } else {
          const token = (settings.tokens || []).find((item) => item.id === zone.tokenId);
          if (!zoneSslCache.has(zone.id) && token?.apiToken) {
            try {
              const [mode, certPacks] = await Promise.all([
                getZoneSslMode(token.apiToken, zone.id),
                listZoneCertificatePacks(token.apiToken, zone.id),
              ]);
              zoneSslCache.set(zone.id, { mode, packs: certPacks });
            } catch (error) {
              zoneSslCache.set(zone.id, {
                mode: null,
                packs: [],
                error: error instanceof Error ? error.message : "SSL 查询失败",
              });
            }
          }

          const cached = zoneSslCache.get(zone.id) || {};
          sslMode = cached.mode || null;
          packs = cached.packs || [];
          const match =
            packs.find((pack) =>
              (pack.hosts || []).some(
                (host) =>
                  host === proxy.domain ||
                  host === "*." + zone.name ||
                  (host.startsWith("*.") &&
                    (proxy.domain === host.slice(2) ||
                      proxy.domain.endsWith("." + host.slice(2)))),
              ),
            ) || packs[0] || null;

          if (match) {
            const packStatus = String(match.status || "").toLowerCase();
            if (packStatus === "active") {
              status = "active";
              statusText = "已生效";
            } else if (
              packStatus === "issuing" ||
              packStatus.includes("pending")
            ) {
              status = "pending";
              statusText = "签发中";
            } else if (packStatus) {
              status = "warning";
              statusText = packStatus;
            } else {
              status = "active";
              statusText = "已托管";
            }
            expiresOn = match.expires_on || null;
            autoRenew = match.auto_renew !== false;
            certType = match.type || "universal";
            hosts = match.hosts || hosts;
            issuer = "Cloudflare";
          } else if (cached.error) {
            status = "limited";
            statusText = "需 SSL 读权限";
            autoRenew = true;
            issuer = "Cloudflare";
          } else {
            status = "active";
            statusText = "边缘证书托管";
            autoRenew = true;
            issuer = "Cloudflare";
            certType = "universal";
          }

          if (expiresOn) {
            const exp = new Date(expiresOn).getTime();
            if (!Number.isNaN(exp)) {
              daysLeft = Math.ceil((exp - Date.now()) / 86400000);
              if (daysLeft < 0) {
                status = "warning";
                statusText = "已过期";
              } else if (daysLeft <= 14 && status === "active") {
                statusText = "即将到期";
              }
            }
          } else if (status === "active") {
            // Universal SSL: Cloudflare auto-renews; no fixed end date exposed
            autoRenew = true;
          }
        }

        certificates.push({
          domain: proxy.domain,
          enabled: proxy.enabled !== false,
          origin: createTargetOrigin(proxy.scheme, proxy.targetHost, proxy.targetPort),
          forceHttps: Boolean(proxy.forceHttps),
          hsts: Boolean(proxy.hsts),
          zone: zone?.name || null,
          tokenName: zone?.tokenName || null,
          status,
          statusText,
          sslMode,
          hosts,
          expiresOn,
          daysLeft,
          autoRenew,
          issuer,
          type: certType,
        });
      }

      return jsonResponse({
        configured: true,
        tokenCount: settings.tokens.length,
        certificates,
      });
    } catch (error) {
      return jsonResponse({
        configured: true,
        error: error instanceof Error ? error.message : "证书状态获取失败",
        certificates: proxies.map((proxy) => ({
          domain: proxy.domain,
          enabled: proxy.enabled !== false,
          origin: createTargetOrigin(proxy.scheme, proxy.targetHost, proxy.targetPort),
          forceHttps: Boolean(proxy.forceHttps),
          hsts: Boolean(proxy.hsts),
          zone: null,
          status: "error",
          statusText: "查询失败",
          sslMode: null,
          hosts: [],
          expiresOn: null,
          daysLeft: null,
          autoRenew: null,
          issuer: null,
          type: null,
        })),
      });
    }
  }

  if (url.pathname === "/api/cloudflare/zones" && request.method === "GET") {
    const settings = await getCloudflareSettings(env.PROXY_CONFIG);
    if (!(settings?.tokens || []).length) {
      return jsonResponse(
        { error: "未绑定 Cloudflare API", configured: false, zones: [] },
        400,
      );
    }

    try {
      const zones = await listZonesFromAllTokens(settings);
      await env.PROXY_CONFIG.put(CF_SETTINGS_KEY, JSON.stringify(settings));
      return jsonResponse({
        configured: true,
        tokenCount: settings.tokens.length,
        zones: zones.map((z) => ({
          id: z.id,
          name: z.name,
          status: z.status,
          plan: z.plan || "",
          tokenId: z.tokenId,
          tokenName: z.tokenName,
        })),
      });
    } catch (error) {
      return jsonResponse(
        { error: error instanceof Error ? error.message : "拉取域名失败" },
        502,
      );
    }
  }

  if (url.pathname.startsWith("/api/cloudflare/zones/") && url.pathname.endsWith("/dns") && request.method === "GET") {
    const settings = await getCloudflareSettings(env.PROXY_CONFIG);
    if (!(settings?.tokens || []).length) {
      return jsonResponse({ error: "未绑定 Cloudflare API", records: [] }, 400);
    }
    const zoneId = decodeURIComponent(
      url.pathname.slice("/api/cloudflare/zones/".length, -"/dns".length),
    );
    if (!zoneId) {
      return jsonResponse({ error: "zone id 无效" }, 400);
    }
    try {
      const zones = await listZonesFromAllTokens(settings);
      const zone = zones.find((item) => item.id === zoneId);
      const token = (settings.tokens || []).find((item) => item.id === zone?.tokenId) || settings.tokens[0];
      const records = await listCloudflareDnsRecords(token.apiToken, zoneId);
      return jsonResponse({
        records: records.map((r) => ({
          id: r.id,
          type: r.type,
          name: r.name,
          content: r.content,
          proxied: r.proxied,
        })),
      });
    } catch (error) {
      return jsonResponse(
        { error: error instanceof Error ? error.message : "拉取 DNS 记录失败" },
        502,
      );
    }
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

  // 添加自定义请求头
  if (Array.isArray(config.customHeaders)) {
    for (const { name, value } of config.customHeaders) {
      if (name && value) {
        headers.set(name, value);
      }
    }
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



function findZoneForHostname(hostname, zones) {
  const host = normalizeHostname(hostname);
  if (!host || !Array.isArray(zones) || !zones.length) return null;

  let best = null;
  for (const zone of zones) {
    const zoneName = normalizeHostname(zone?.name || zone);
    if (!zoneName) continue;
    if (host === zoneName || host.endsWith("." + zoneName)) {
      if (!best || zoneName.length > normalizeHostname(best.name || best).length) {
        best = typeof zone === "string" ? { name: zoneName } : { ...zone, name: zoneName };
      }
    }
  }
  return best;
}


async function getAdminSettings(kv) {
  if (!kv?.get) return null;
  return (await kv.get(ADMIN_SETTINGS_KEY, "json")) || null;
}

async function hashAdminPassword(password, secret) {
  const key = await importHmacKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(password)),
  );
  return toBase64Url(new Uint8Array(signature));
}

async function verifyAdminPassword(env, password) {
  const override = await getAdminSettings(env.PROXY_CONFIG);
  if (override?.passwordHash) {
    const actualHash = await hashAdminPassword(password, env.SESSION_SECRET);
    return secureStringEqual(actualHash, String(override.passwordHash));
  }
  return secureEqual(password, env.ADMIN_PASSWORD, env.SESSION_SECRET);
}

function secureStringEqual(a, b) {
  const left = String(a);
  const right = String(b);
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) {
    diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  }
  return diff === 0;
}

async function getCloudflareSettings(kv) {
  if (!kv?.get) return null;
  const raw = (await kv.get(CF_SETTINGS_KEY, "json")) || null;
  return normalizeCloudflareSettings(raw);
}

function normalizeCloudflareSettings(raw) {
  if (!raw) {
    return { tokens: [] };
  }
  // migrate legacy single-token shape
  if (Array.isArray(raw.tokens)) {
    return {
      tokens: raw.tokens
        .filter((item) => item && item.apiToken)
        .map((item) => ({
          id: item.id || cryptoRandomId(),
          name: item.name || item.accountName || "Cloudflare",
          apiToken: item.apiToken,
          accountName: item.accountName || "",
          verifiedAt: item.verifiedAt || "",
          zoneCount: item.zoneCount ?? null,
        })),
    };
  }
  if (raw.apiToken) {
    return {
      tokens: [
        {
          id: raw.id || cryptoRandomId(),
          name: raw.accountName || "Cloudflare",
          apiToken: raw.apiToken,
          accountName: raw.accountName || "",
          verifiedAt: raw.verifiedAt || "",
          zoneCount: raw.zoneCount ?? null,
        },
      ],
    };
  }
  return { tokens: [] };
}

function cryptoRandomId() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  }
  return String(Date.now()) + Math.random().toString(16).slice(2, 8);
}

function maskToken(token) {
  const value = String(token || "");
  if (value.length <= 10) return "********";
  return value.slice(0, 4) + "..." + value.slice(-4);
}

function publicCloudflareSettings(settings) {
  const tokens = (settings?.tokens || []).map((item) => ({
    id: item.id,
    name: item.name || item.accountName || "Cloudflare",
    accountName: item.accountName || "",
    verifiedAt: item.verifiedAt || "",
    zoneCount: item.zoneCount ?? null,
    maskedToken: maskToken(item.apiToken),
  }));
  return {
    configured: tokens.length > 0,
    tokenCount: tokens.length,
    tokens,
  };
}

async function listZonesFromAllTokens(settings) {
  const tokens = settings?.tokens || [];
  const zoneMap = new Map(); // zoneId -> zone+tokenId
  for (const token of tokens) {
    try {
      const zones = await listCloudflareZones(token.apiToken);
      token.zoneCount = zones.length;
      token.verifiedAt = new Date().toISOString();
      for (const zone of zones) {
        if (!zoneMap.has(zone.id)) {
          zoneMap.set(zone.id, {
            ...zone,
            tokenId: token.id,
            tokenName: token.name || token.accountName || "Cloudflare",
          });
        }
      }
    } catch (error) {
      // keep other tokens working
      console.error(
        JSON.stringify({
          event: "cf_token_zones_failed",
          tokenId: token.id,
          message: error instanceof Error ? error.message : String(error),
        }),
      );
    }
  }
  return Array.from(zoneMap.values()).sort((a, b) => a.name.localeCompare(b.name));
}

async function findTokenAndZoneForHostname(settings, hostname) {
  const zones = await listZonesFromAllTokens(settings);
  const zone = findZoneForHostname(hostname, zones);
  if (!zone) return { zone: null, token: null, zones };
  const token = (settings.tokens || []).find((item) => item.id === zone.tokenId) || null;
  return { zone, token, zones };
}

async function cloudflareApi(apiToken, path) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
    },
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Cloudflare API 返回异常 (${response.status})`);
  }

  if (!response.ok || payload?.success === false) {
    const msg =
      payload?.errors?.[0]?.message ||
      payload?.messages?.[0] ||
      `Cloudflare API 错误 (${response.status})`;
    throw new Error(msg);
  }

  return payload;
}

async function verifyCloudflareToken(apiToken) {
  const payload = await cloudflareApi(apiToken, "/user/tokens/verify");
  const status = payload?.result?.status;
  if (status && status !== "active") {
    throw new Error(`Token 状态不可用：${status}`);
  }

  let accountName = "";
  try {
    const user = await cloudflareApi(apiToken, "/user");
    accountName = user?.result?.email || user?.result?.username || "";
  } catch {
    // token may be account-owned without /user scope
    try {
      const accounts = await cloudflareApi(apiToken, "/accounts?per_page=1");
      accountName = accounts?.result?.[0]?.name || "";
    } catch {
      accountName = "";
    }
  }

  return { accountName, status: status || "active" };
}

async function listCloudflareZones(apiToken) {
  const zones = [];
  let page = 1;

  while (page <= 20) {
    const payload = await cloudflareApi(
      apiToken,
      `/zones?page=${page}&per_page=50&status=active`,
    );
    const batch = payload?.result || [];
    for (const zone of batch) {
      zones.push({
        id: zone.id,
        name: normalizeHostname(zone.name),
        status: zone.status || "",
        plan: zone.plan?.name || "",
      });
    }
    const info = payload?.result_info;
    if (!info || page >= (info.total_pages || 1) || batch.length === 0) break;
    page += 1;
  }

  zones.sort((a, b) => a.name.localeCompare(b.name));
  return zones;
}


async function getZoneSslMode(apiToken, zoneId) {
  try {
    const payload = await cloudflareApi(
      apiToken,
      `/zones/${encodeURIComponent(zoneId)}/settings/ssl`,
    );
    return payload?.result?.value || null;
  } catch {
    return null;
  }
}

async function listZoneCertificatePacks(apiToken, zoneId) {
  try {
    const payload = await cloudflareApi(
      apiToken,
      `/zones/${encodeURIComponent(zoneId)}/ssl/certificate_packs?status=all`,
    );
    const packs = payload?.result || [];
    return packs.map((pack) => ({
      id: pack.id,
      type: pack.type,
      status: pack.status,
      hosts: pack.hosts || [],
      expires_on:
        pack.expires_on ||
        pack.certificate_authority_expires_on ||
        pack.certificate_authority?.expires_on ||
        null,
      validity_days: pack.validity_days || pack.primary_certificate?.validity_days || null,
      // Cloudflare-managed packs are auto-renewed
      auto_renew: pack.auto_renew !== false,
    }));
  } catch {
    // Token may lack SSL read permission; fail soft.
    return [];
  }
}

async function listCloudflareDnsRecords(apiToken, zoneId) {
  const records = [];
  let page = 1;

  while (page <= 20) {
    const payload = await cloudflareApi(
      apiToken,
      `/zones/${encodeURIComponent(zoneId)}/dns_records?page=${page}&per_page=100`,
    );
    const batch = payload?.result || [];
    for (const record of batch) {
      if (!["A", "AAAA", "CNAME"].includes(record.type)) continue;
      records.push({
        id: record.id,
        type: record.type,
        name: normalizeHostname(record.name),
        content: record.content,
        proxied: Boolean(record.proxied),
      });
    }
    const info = payload?.result_info;
    if (!info || page >= (info.total_pages || 1) || batch.length === 0) break;
    page += 1;
  }

  records.sort((a, b) => a.name.localeCompare(b.name));
  return records;
}

async function ensureWorkerRoute(apiToken, zoneId, hostname, zoneName, workerName) {
  // Check if DNS record exists
  const records = await listCloudflareDnsRecords(apiToken, zoneId);
  const existingRecord = records.find(r => r.name === hostname);

  // Get subdomain part (e.g., "api" from "api.hx10.com")
  const subdomain = hostname.replace(`.${zoneName}`, "") || "@";

  if (!existingRecord) {
    // Create DNS record pointing to Worker (placeholder IP, proxied)
    await cloudflareApiPost(
      apiToken,
      `/zones/${encodeURIComponent(zoneId)}/dns_records`,
      {
        type: "A",
        name: subdomain,
        content: "192.0.2.1",
        proxied: true,
        comment: "Edge Proxy Manager auto-created",
        ttl: 1,
      },
    );
  } else if (!existingRecord.proxied) {
    // Enable proxying if not already
    await cloudflareApiPatch(
      apiToken,
      `/zones/${encodeURIComponent(zoneId)}/dns_records/${existingRecord.id}`,
      { proxied: true },
    );
  }

  // Add worker route
  try {
    await cloudflareApiPost(
      apiToken,
      `/zones/${encodeURIComponent(zoneId)}/workers/routes`,
      { pattern: `${hostname}/*`, script: workerName },
    );
  } catch (e) {
    // Route may already exist, ignore
  }
}

async function cloudflareApiPost(apiToken, path, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Cloudflare API 返回异常 (${response.status})`);
  }

  if (!response.ok || payload?.success === false) {
    const msg =
      payload?.errors?.[0]?.message ||
      payload?.messages?.[0] ||
      `Cloudflare API 错误 (${response.status})`;
    throw new Error(msg);
  }

  return payload;
}

async function cloudflareApiPatch(apiToken, path, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Cloudflare API 返回异常 (${response.status})`);
  }

  if (!response.ok || payload?.success === false) {
    const msg =
      payload?.errors?.[0]?.message ||
      payload?.messages?.[0] ||
      `Cloudflare API 错误 (${response.status})`;
    throw new Error(msg);
  }

  return payload;
}

async function cloudflareApiWithBody(apiToken, path, method, body) {
  const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Cloudflare API 返回异常 (${response.status})`);
  }

  if (!response.ok || payload?.success === false) {
    const msg =
      payload?.errors?.[0]?.message ||
      payload?.messages?.[0] ||
      `Cloudflare API 错误 (${response.status})`;
    throw new Error(msg);
  }

  return payload;
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

  // 处理自定义请求头
  const customHeaders = parseCustomHeaders(input.customHeadersText);

  return {
    config: {
      domain,
      scheme,
      targetHost,
      targetPort,
      landingPath,
      landingHash,
      locations: locationResult.locations,
      customHeaders,
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

function parseCustomHeaders(value) {
  const lines = String(value || "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const headers = [];

  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator < 1) {
      continue; // 跳过无效行
    }

    const name = line.slice(0, separator).trim();
    const headerValue = line.slice(separator + 1).trim();

    if (name && headerValue) {
      headers.push({ name, value: headerValue });
    }
  }

  return headers;
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
    <div class="brand"><div class="logo">EP</div><div><h1>Edge Proxy Manager</h1><p>边缘反向代理</p></div></div>
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
    .app-header{height:var(--header-height);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:center;padding:0;position:relative;z-index:80;overflow:visible}.app-header-inner{height:100%;width:100%;max-width:1140px;padding:0 18px;display:flex;align-items:center;justify-content:space-between;position:relative;overflow:visible}.brand{display:flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;font-size:16px;font-weight:720;letter-spacing:-.01em}.brand-logo{width:30px;height:30px;display:grid;place-items:center;clip-path:polygon(50% 0,92% 24%,92% 76%,50% 100%,8% 76%,8% 24%);background:conic-gradient(from 25deg,#ff8b00,#f13576,#7657df,#1971c2,#ff8b00);padding:3px;filter:drop-shadow(0 3px 6px rgba(90,68,181,.14))}.brand-logo span{width:100%;height:100%;display:grid;place-items:center;clip-path:inherit;background:var(--surface);color:#6f56d9;font-size:11px;font-weight:900}.header-actions{display:flex;align-items:center;gap:10px;position:relative;z-index:90;overflow:visible}.language{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px}.icon-button{width:40px;height:40px;border:0;border-radius:9px;background:transparent;display:grid;place-items:center;cursor:pointer;color:var(--text)}.icon-button:hover{background:var(--surface-hover)}.sun-icon{display:none}:root[data-theme="dark"] .moon-icon{display:none}:root[data-theme="dark"] .sun-icon{display:block}.account-menu{position:relative}.account-menu summary{list-style:none;display:flex;align-items:center;gap:10px;padding:5px 7px;border-radius:10px;cursor:pointer}.account-menu summary::-webkit-details-marker{display:none}.account-menu summary:hover{background:var(--surface-hover)}.avatar{width:42px;height:42px;border-radius:10px;border:1px solid var(--border);background:linear-gradient(145deg,#d8dde5,#fff);display:grid;place-items:center;color:#8b95a3;font-weight:850}.account-copy{display:flex;flex-direction:column;min-width:78px;line-height:1.25}.account-copy strong{font-size:14px}.account-copy small{font-size:12px;color:var(--muted)}.account-dropdown{position:fixed;top:0;right:0;width:180px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:8px;box-shadow:0 12px 32px rgba(17,24,39,.18);z-index:10000;display:none}.account-menu[open] > .account-dropdown{display:block}.account-dropdown form{margin:0}.account-dropdown button{width:100%;border:0;background:transparent;border-radius:7px;text-align:left;padding:10px 12px;cursor:pointer;color:var(--text)}.account-dropdown button:hover{background:var(--surface-hover)}
    .app-nav{height:var(--nav-height);background:var(--surface);border-bottom:1px solid var(--border);position:relative;z-index:30}.nav-inner{height:100%;max-width:1140px;margin:0 auto;display:flex;align-items:center;gap:2px;padding:0 18px;width:100%}.nav-link{height:var(--nav-height);border:0;background:transparent;color:var(--muted);display:flex;align-items:center;gap:7px;padding:0 12px;text-decoration:none;font-size:13px;font-weight:620;border-bottom:2px solid transparent;cursor:pointer;white-space:nowrap}.nav-link:hover,.nav-link.active,.nav-dropdown.active>.nav-link{color:var(--text);background:var(--surface-soft);border-bottom-color:var(--green)}.nav-link .chevron{width:14px;height:14px;transition:transform .18s}.app-nav{z-index:30}.nav-dropdown{height:100%;position:relative}.nav-dropdown.open .chevron,.nav-dropdown:focus-within .chevron{transform:rotate(180deg)}.nav-menu{position:absolute;left:0;top:100%;width:230px;background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:8px;box-shadow:0 16px 38px rgba(31,42,57,.15);opacity:0;visibility:hidden;pointer-events:none;transform:translateY(4px);transition:.12s;z-index:80}.nav-menu::before{content:"";position:absolute;left:0;right:0;top:-10px;height:10px}.nav-dropdown.open .nav-menu,.nav-dropdown:focus-within .nav-menu{opacity:1;visibility:visible;pointer-events:auto;transform:none}.nav-menu a{display:flex;align-items:center;gap:10px;color:var(--text);text-decoration:none;border-radius:7px;padding:11px 12px;font-size:14px;cursor:pointer}.nav-menu a:hover,.nav-menu a.active{background:var(--surface-hover);color:var(--green-dark)}
    .layout{width:100%;max-width:1140px;margin:0 auto;padding:16px 18px 28px;flex:1}.view{display:none}.view.active{display:block;animation:fadeIn .18s ease}@keyframes fadeIn{from{opacity:.5;transform:translateY(3px)}to{opacity:1;transform:none}}.view-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}.view-heading h1{font-size:16px;letter-spacing:0;margin:0 0 2px;font-weight:700}.view-heading p{margin:0;color:var(--muted);font-size:12px}.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:12px}.stat-card{min-height:0;background:var(--surface);border:1px solid var(--border);border-radius:6px;box-shadow:none;display:flex;align-items:center;gap:12px;padding:14px 16px;transition:none}.stat-card:hover{transform:none;box-shadow:none}.stat-icon{width:38px;height:38px;border-radius:6px;color:#fff;display:grid;place-items:center;flex:0 0 auto}.stat-icon.green{background:#2fb344}.stat-icon.orange{background:var(--orange)}.stat-icon.blue{background:var(--blue)}.stat-icon.red{background:var(--red)}.stat-icon .icon{width:18px;height:18px;stroke-width:2}.stat-copy{display:flex;align-items:center;gap:6px;min-width:0;flex-wrap:wrap}.stat-copy strong{font-size:15px;letter-spacing:0;font-weight:700}.stat-copy span{color:var(--text);font-size:14px;white-space:nowrap;font-weight:500}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:10px}.panel{background:var(--surface);border:1px solid var(--border);border-radius:6px;box-shadow:none;overflow:hidden}.panel-accent-green{border-top:2px solid var(--green)}.panel-accent-pink{border-top:2px solid var(--pink)}.panel-head{min-height:0;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 16px}.panel-head h2{font-size:15px;margin:0;font-weight:700}.panel-subtitle{font-size:12px;color:var(--muted);margin-top:1px}.help-button{width:28px;height:28px;border:1px solid var(--border);border-radius:6px;background:var(--surface);display:grid;place-items:center;color:var(--muted);cursor:pointer}.help-button:hover{background:var(--surface-hover);color:var(--text)}.recent-list{min-height:0}.recent-row{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr) 88px;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--border)}.recent-row:last-child{border-bottom:0}.recent-domain{font-weight:720}.recent-target{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:left}.button{border:0;border-radius:6px;padding:8px 12px;font-weight:650;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:6px;text-decoration:none;font-size:13px}.button.is-disabled,.button:disabled{opacity:.55;cursor:not-allowed;pointer-events:none}.button-primary{background:var(--green);color:#fff;box-shadow:0 4px 10px rgba(92,165,0,.2)}.button-primary:hover{background:var(--green-dark)}.button-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border)}.button-secondary:hover{background:var(--surface-hover)}.button-danger{background:transparent;color:#c92a2a;border:1px solid #f1b8b8}.button-danger:hover{background:#fff1f1}.button-sm{padding:5px 10px;font-size:12px;border-radius:6px}.button .icon{width:17px;height:17px}
    .table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:720px}th,td{text-align:left;padding:11px 16px;border-bottom:1px solid var(--border);font-size:13px}th{background:var(--surface-soft);color:var(--muted);font-size:12px;font-weight:750;text-transform:uppercase;letter-spacing:.045em}tbody tr:hover{background:var(--surface-soft)}tbody tr:last-child td{border-bottom:0}.domain-cell{display:flex;align-items:center;gap:11px}.domain-dot{width:9px;height:9px;border-radius:50%;background:#adb5bd;box-shadow:0 0 0 4px rgba(173,181,189,.15)}.domain-dot.enabled{background:#2fb344;box-shadow:0 0 0 4px rgba(47,179,68,.13)}.domain-name{font-weight:750}.domain-link{color:var(--blue);text-decoration:none}.domain-link:hover{text-decoration:underline}.recent-domain.domain-link{font-weight:720}.quick-url-field{margin-bottom:12px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--surface-soft)}.quick-url-field > label{margin-bottom:6px}.quick-url-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}.quick-url-row input{width:100%;min-height:38px}.quick-url-field .hint{margin-top:6px}.target{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted);font-size:12px}.badge{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:650;min-width:52px}.badge.on{background:#e9f8d6;color:#477c00}.badge.off{background:#edf0f4;color:#697586}.actions{display:flex;gap:8px}.empty-state{min-height:0;padding:40px 16px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}.empty-icon{width:44px;height:44px;border-radius:12px;background:var(--green-soft);color:var(--green-dark);display:grid;place-items:center;margin-bottom:10px}.empty-icon .icon{width:22px;height:22px}.empty-state h2{font-size:16px;margin:0 0 4px}.empty-state p{color:var(--muted);font-size:12px;margin:0 0 14px}.compact-empty{min-height:0;padding:28px 16px}.managed-state{min-height:0;padding:40px 16px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center}.managed-state .empty-icon{background:#fff0f6;color:var(--pink)}.managed-state h2{font-size:22px;margin:0 0 8px}.managed-state p{max-width:620px;color:var(--muted);line-height:1.7;margin:0}.managed-tags{display:flex;gap:9px;flex-wrap:wrap;justify-content:center;margin-top:22px}.managed-tag{background:var(--surface-soft);border:1px solid var(--border);border-radius:999px;padding:7px 11px;color:var(--muted);font-size:12px}.settings-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.setting-card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:24px;box-shadow:0 3px 12px rgba(32,43,58,.04)}.setting-card .setting-icon{width:44px;height:44px;border-radius:10px;background:var(--surface-soft);display:grid;place-items:center;color:var(--green-dark);margin-bottom:18px}.setting-card h2{font-size:17px;margin:0 0 8px}.setting-card p{font-size:13px;color:var(--muted);line-height:1.7;margin:0}.page-footer{min-height:44px;background:var(--surface);border-top:1px solid var(--border);display:flex;align-items:center;justify-content:center;padding:0;color:var(--muted);font-size:12px}.page-footer-inner{width:100%;max-width:1140px;padding:0 18px;display:flex;align-items:center;justify-content:space-between;gap:12px}
    
    
    .cf-help-box{margin:0 0 14px;padding:12px 14px;border:1px solid var(--border);border-radius:8px;background:var(--surface-soft)}
    .cf-help-title{font-size:13px;font-weight:700;margin:0 0 8px;color:var(--text)}
    .cf-help-steps{margin:0 0 8px;padding-left:18px;color:var(--muted);font-size:12px;line-height:1.7}
    .cf-help-steps li{margin:0 0 4px}
    .cf-help-box a{color:var(--blue);text-decoration:none;word-break:break-all}
    .cf-help-box a:hover{text-decoration:underline}
.cf-settings-panel{margin-bottom:4px}.cf-settings-body{padding:14px 16px 16px}.cf-settings-desc{margin:0 0 12px;color:var(--muted);font-size:13px;line-height:1.6}
    .cf-settings-actions{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
    .cf-meta{font-size:12px;color:var(--muted);margin-bottom:10px}
    .cf-status{display:inline-flex;align-items:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:650;background:#edf0f4;color:#697586}
    .cf-status.on{background:#e9f8d6;color:#477c00}.cf-status.err{background:#ffe3e3;color:#c92a2a}
    
    .cf-token-form{grid-template-columns:0.8fr 1.4fr;gap:12px;margin-bottom:4px}
    .cf-token-list{display:flex;flex-direction:column;gap:8px;margin:10px 0 12px}
    .cf-token-item{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;background:var(--surface)}
    .cf-token-item .meta{min-width:0}
    .cf-token-item .name{font-weight:700;font-size:13px}
    .cf-token-item .sub{color:var(--muted);font-size:12px;margin-top:2px;word-break:break-all}
    .cf-token-item .actions{display:flex;gap:8px;flex:0 0 auto}
    .cert-renew-yes{color:#477c00;font-weight:650}
    .cert-renew-no{color:#c92a2a;font-weight:650}
    .cert-expiry-warn{color:#9c6b00;font-weight:650}
.cf-zone-list{display:flex;flex-wrap:wrap;gap:8px}
    .zone-chip,.zone-chip-btn{border:1px solid var(--border);background:var(--surface);border-radius:999px;padding:5px 10px;font-size:12px;color:var(--text)}
    .zone-chip-btn{cursor:pointer}.zone-chip-btn:hover{border-color:var(--blue);color:var(--blue)}
    .domain-picker{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center}
    .zone-chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
dialog{width:min(760px,calc(100% - 24px));max-height:calc(100vh - 28px);border:0;border-radius:10px;padding:0;background:var(--surface);color:var(--text);box-shadow:0 20px 70px rgba(17,24,39,.28)}dialog::backdrop{background:rgba(23,31,43,.66);backdrop-filter:blur(2px)}.modal-form{display:flex;flex-direction:column;max-height:calc(100vh - 36px)}.modal-head{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}.modal-title{display:flex;align-items:center;gap:12px}.modal-title-mark{width:36px;height:36px;border-radius:9px;background:var(--green-soft);color:var(--green-dark);display:grid;place-items:center}.modal-head h2{margin:0;font-size:20px}.close-button{width:38px;height:38px;border:0;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer;display:grid;place-items:center}.close-button:hover{background:var(--surface-hover);color:var(--text)}.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 22px}.tab{border:0;background:transparent;padding:15px 17px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent}.tab.active{color:var(--text);border-bottom-color:var(--green);font-weight:750}.modal-body{overflow:auto}.tab-panel{display:none;padding:14px 16px}.tab-panel.active{display:block}.grid{display:grid;grid-template-columns:1fr 1.5fr .7fr;gap:15px}.field{margin-bottom:12px}.field label{display:block;font-size:13px;font-weight:750;margin-bottom:7px}.field input,.field select,.field textarea{width:100%;border:1px solid var(--border);border-radius:8px;padding:11px 12px;outline:none;background:var(--surface);color:var(--text)}.field textarea{min-height:170px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--green);box-shadow:0 0 0 3px rgba(108,190,8,.14)}.hint{color:var(--muted);font-size:12px;margin-top:6px;line-height:1.6}.switches{display:grid;grid-template-columns:1fr 1fr;gap:12px}.switch{display:flex;align-items:center;justify-content:space-between;border:1px solid var(--border);border-radius:9px;padding:13px 14px;background:var(--surface-soft)}.switch input{width:19px;height:19px;accent-color:var(--green)}.info{background:#eff6ff;border:1px solid #cfe1ff;color:#385777;border-radius:9px;padding:14px;font-size:13px;line-height:1.7}:root[data-theme="dark"] .info{background:#202d42;border-color:#31476a;color:#b7cef3}.modal-foot{display:flex;justify-content:space-between;padding:12px 16px;border-top:1px solid var(--border);background:var(--surface-soft)}
    
    .cert-summary{margin-bottom:12px}
    .cert-badge{display:inline-flex;align-items:center;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:650}
    .cert-badge.active{background:#e9f8d6;color:#477c00}
    .cert-badge.pending,.cert-badge.limited{background:#fff3bf;color:#9c6b00}
    .cert-badge.warning,.cert-badge.unmanaged,.cert-badge.error,.cert-badge.unknown{background:#ffe3e3;color:#c92a2a}
    .cert-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--muted)}

    #editor{width:min(700px,calc(100% - 24px));border-radius:12px}
    #editor .modal-head{padding:16px 20px}
    #editor .modal-body{background:var(--surface)}
    #editor .tabs{padding:0 20px}
    #editor .tab{padding:12px 14px;font-size:13px;font-weight:650}
    #editor .tab-panel{padding:18px 20px 20px}
    .proxy-details-panel{display:none}
    .proxy-details-panel.active{display:block}
    .form-section{padding:14px;border:1px solid var(--border);border-radius:10px;background:var(--surface);margin-bottom:12px}
    .origin-section{background:var(--surface-soft)}
    .section-heading{display:flex;align-items:flex-start;gap:9px;margin:0 0 12px}
    .section-heading h3{font-size:14px;line-height:1.3;margin:0;color:var(--text)}
    .section-heading p{font-size:12px;line-height:1.4;margin:3px 0 0;color:var(--muted)}
    .section-step{width:20px;height:20px;border-radius:50%;background:var(--green-soft);color:var(--green-dark);font-size:12px;font-weight:750;display:grid;place-items:center;flex:0 0 auto}
    #editor .field{margin-bottom:0}
    #editor .field label{font-size:12px;margin-bottom:6px}
    .quick-url-field{margin:0 0 12px;padding:0;border:0;background:transparent}
    .quick-url-field > label{font-size:12px;font-weight:650;margin-bottom:6px}
    .quick-url-field > label span{color:var(--muted);font-weight:400}
    .quick-url-row input{min-height:40px}
    .source-grid{display:grid;grid-template-columns:100px minmax(0,1fr) 90px;gap:10px}
    .entry-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
    .advanced-options{border:1px solid var(--border);border-radius:9px;background:var(--surface);overflow:hidden}
    .advanced-options summary{cursor:pointer;list-style:none;padding:12px 14px;font-size:13px;font-weight:650;display:flex;align-items:center;justify-content:space-between}
    .advanced-options summary::-webkit-details-marker{display:none}
    .advanced-options summary::after{content:"⌄";color:var(--muted);font-size:16px;transition:transform .15s}
    .advanced-options[open] summary{border-bottom:1px solid var(--border)}
    .advanced-options[open] summary::after{transform:rotate(180deg)}
    .advanced-content{padding:14px}
    .compact-switches{grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:12px}
    .compact-switches .switch{padding:10px 11px;border-radius:8px;font-size:12px}
    .rule-panel .section-heading{margin-bottom:16px}
    @media(max-width:640px){
      #editor .modal-head{padding:14px 16px}
      #editor .tabs,#editor .tab-panel{padding-left:16px;padding-right:16px}
      .source-grid,.entry-grid{grid-template-columns:1fr}
      .compact-switches{grid-template-columns:1fr}
      .quick-url-row{grid-template-columns:1fr}
      .domain-picker{grid-template-columns:1fr}
    }

    .dialog-sm{width:min(420px,calc(100% - 24px));border-radius:12px;overflow:hidden}
    .password-body{padding:18px 20px 8px}
    .password-body .field{margin-bottom:14px}
    .password-body .field:last-child{margin-bottom:10px}
    .password-body .field label{display:block;font-size:13px;font-weight:650;color:var(--text);margin:0 0 8px}
    .password-body .field input{display:block;width:100%;box-sizing:border-box;min-height:42px;border:1px solid var(--border);border-radius:8px;padding:10px 12px;background:var(--surface);color:var(--text)}
    .password-body .field input:focus{border-color:var(--green);box-shadow:0 0 0 3px rgba(108,190,8,.14);outline:none}
    .password-foot{display:flex;justify-content:flex-end;gap:8px;padding:12px 20px;border-top:1px solid var(--border);background:var(--surface-soft)}
    .password-foot .button{min-width:84px}
.toast{position:fixed;right:24px;bottom:24px;background:#263444;color:#fff;padding:12px 16px;border-radius:9px;opacity:0;transform:translateY(12px);pointer-events:none;transition:.2s;z-index:100}.toast.show{opacity:1;transform:none}.toast.error{background:#b42318}
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
        <div class="account-dropdown">
          <button type="button" id="openPasswordDialog">修改密码</button>
          <form method="post" action="/logout"><button type="submit">退出登录</button></form>
        </div>
      </details>
    </div>
    </div></header>
  <nav class="app-nav" aria-label="主导航">
    <div class="nav-inner">
      <a class="nav-link active" href="#dashboard" data-view-link="dashboard"><svg class="icon" viewBox="0 0 24 24"><path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v10h13V10M9.5 20v-6h5v6"/></svg><span>仪表板</span></a>
      <a class="nav-link" href="#proxies" data-view-link="proxies" id="navProxiesLink"><svg class="icon" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg><span>主机列表</span></a>
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
    <section class="view" data-view="proxies" id="proxiesView">
      <div class="view-heading"><div><h1>代理服务列表</h1></div><button class="button button-primary open-editor" id="headerAddProxy" type="button" hidden><svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>添加代理服务</button></div>
      <section class="panel panel-accent-green">
        <div class="panel-head" id="proxyPanelHead" hidden><div><h2>主机列表</h2></div><button class="help-button" type="button" title="需绑定到当前 Worker"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.8 9a2.4 2.4 0 1 1 3.3 2.2c-.8.4-1.1.9-1.1 1.8M12 17h.01"/></svg></button></div>
        <div class="table-wrap" id="proxyTableWrap" hidden><table><thead><tr><th>域名</th><th>转发目标</th><th>状态</th><th>WebSocket</th><th>更新时间</th><th>操作</th></tr></thead><tbody id="proxyRows"></tbody></table></div>
        <div class="empty-state" id="emptyState"><span class="empty-icon"><svg class="icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/><circle cx="5" cy="12" r="2"/></svg></span><h2>暂无代理</h2><p>添加第一条代理规则</p><button class="button button-primary open-editor" type="button"><svg class="icon" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>添加代理服务</button></div>
      </section>
    </section>
    <section class="view" data-view="certificates">
      <div class="view-heading">
        <div><h1>证书状态</h1></div>
        <button class="button button-secondary button-sm" type="button" id="refreshCertificates">刷新</button>
      </div>
      <div class="summary cert-summary">
        <article class="stat-card"><span class="stat-icon green"><svg class="icon" viewBox="0 0 24 24"><path d="M12 3 20 7v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4Z"/><path d="m9 12 2 2 4-4"/></svg></span><div class="stat-copy"><strong id="certActiveCount">0</strong><span>已生效</span></div></article>
        <article class="stat-card"><span class="stat-icon orange"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16h.01"/></svg></span><div class="stat-copy"><strong id="certPendingCount">0</strong><span>处理中</span></div></article>
        <article class="stat-card"><span class="stat-icon red"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></svg></span><div class="stat-copy"><strong id="certIssueCount">0</strong><span>异常/未托管</span></div></article>
        <article class="stat-card"><span class="stat-icon blue"><svg class="icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/><circle cx="5" cy="12" r="2"/></svg></span><div class="stat-copy"><strong id="certTotalCount">0</strong><span>代理域名</span></div></article>
      </div>
      <section class="panel panel-accent-pink">
        <div class="panel-head">
          <div><h2>域名证书</h2></div>
          <span class="cf-status" id="certCfBadge">—</span>
        </div>
        <div class="table-wrap" id="certTableWrap" hidden>
          <table>
            <thead>
              <tr>
                <th>域名</th>
                <th>Zone</th>
                <th>状态</th>
                <th>到期时间</th>
                <th>自动续签</th>
                <th>SSL 模式</th>
                <th>回源</th>
              </tr>
            </thead>
            <tbody id="certRows"></tbody>
          </table>
        </div>
        <div class="empty-state" id="certEmpty">
          <span class="empty-icon"><svg class="icon" viewBox="0 0 24 24"><path d="M12 3 20 7v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4Z"/><path d="m9 12 2 2 4-4"/></svg></span>
          <h2>暂无证书数据</h2>
          <p id="certEmptyText">添加代理后显示证书状态</p>
        </div>
      </section>
    </section>
    <section class="view" data-view="settings">
      <div class="view-heading"><div><h1>设置</h1></div></div>
      <section class="panel cf-settings-panel">
        <div class="panel-head"><div><h2>Cloudflare API</h2></div><span class="cf-status" id="cfStatusBadge">未绑定</span></div>
        <div class="cf-settings-body">
          <div class="cf-help-box">
            <div class="cf-help-title">获取 API 令牌</div>
            <ol class="cf-help-steps">
              <li>Cloudflare 头像 → <strong>配置文件</strong> → <strong>API 令牌</strong></li>
              <li><a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer">dash.cloudflare.com/profile/api-tokens</a></li>
              <li>权限：区域 → 区域 → 读取；区域 → DNS → 编辑；区域 → Workers Routes → 编辑</li>
              <li>可添加多个令牌；不要用 Global API Key</li>
            </ol>
          </div>
          <div class="grid cf-token-form">
            <div class="field"><label for="cfTokenName">备注名</label><input id="cfTokenName" placeholder="例如 主账号 / 客户A" autocomplete="off"></div>
            <div class="field"><label for="cfApiToken">API 令牌</label><input id="cfApiToken" type="password" autocomplete="off" placeholder="粘贴 API 令牌"></div>
          </div>
          <div class="cf-settings-actions">
            <button type="button" class="button button-primary" id="saveCfToken">添加令牌</button>
            <button type="button" class="button button-secondary" id="refreshCfZones">刷新域名</button>
          </div>
          <div class="cf-meta" id="cfMeta">未绑定</div>
          <div class="cf-token-list" id="cfTokenList"></div>
          <div class="cf-zone-list" id="cfZoneList"></div>
        </div>
      </section>
    </section>
  </main>
  <footer class="page-footer"><div class="page-footer-inner"><span>© 2026 Edge Proxy Manager</span><span class="build-id">build open-source</span><span>Cloudflare Workers</span></div></footer>
  <dialog id="editor">
    <form id="proxyForm" class="modal-form">
      <div class="modal-head"><div class="modal-title"><span class="modal-title-mark"><svg class="icon" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/><circle cx="5" cy="12" r="2"/></svg></span><h2 id="dialogTitle">添加代理服务</h2></div><button type="button" class="close-button" id="closeDialog" aria-label="关闭"><svg class="icon" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
      <div class="tabs"><button type="button" class="tab active" data-tab="details">基础配置</button><button type="button" class="tab" data-tab="locations">路径规则</button><button type="button" class="tab" data-tab="ssl">HTTPS</button></div>
      <div class="modal-body">
        <section class="tab-panel active proxy-details-panel" data-panel="details">
          <input type="hidden" id="originalDomain">

          <section class="form-section domain-section">
            <div class="section-heading"><span class="section-step">1</span><div><h3>代理域名</h3><p>用户访问的公开地址</p></div></div>
            <div class="domain-picker">
              <input id="domain" list="cfDomainSuggestions" placeholder="api.example.com" required autocomplete="off">
              <button type="button" class="button button-secondary button-sm" id="reloadDomainSuggestions" title="刷新 Cloudflare 域名">刷新</button>
            </div>
            <datalist id="cfDomainSuggestions"></datalist>
            <div class="zone-chips" id="zoneChips"></div>
            <div class="hint" id="domainHint">选择已托管域名，或手动输入子域名</div>
          </section>

          <section class="form-section origin-section">
            <div class="section-heading"><span class="section-step">2</span><div><h3>源站地址</h3><p>Worker 将流量转发到这里</p></div></div>
            <div class="quick-url-field">
              <label for="originUrl">粘贴完整源站链接 <span>可选</span></label>
              <div class="quick-url-row">
                <input id="originUrl" placeholder="http://origin.example.com:8080/" autocomplete="off">
                <button type="button" class="button button-secondary button-sm" id="parseOriginUrl">自动填入</button>
              </div>
            </div>
            <div class="source-grid">
              <div class="field"><label for="scheme">协议</label><select id="scheme"><option value="http">HTTP</option><option value="https">HTTPS</option></select></div>
              <div class="field"><label for="targetHost">主机名或 IP</label><input id="targetHost" placeholder="origin.example.com" required></div>
              <div class="field"><label for="targetPort">端口</label><input id="targetPort" type="number" min="1" max="65535" value="80" required></div>
            </div>
          </section>

          <details class="advanced-options">
            <summary>高级选项</summary>
            <div class="advanced-content">
              <div class="entry-grid">
                <div class="field"><label for="landingPath">默认入口路径</label><input id="landingPath" placeholder="/management.html"></div>
                <div class="field"><label for="landingHash">入口 Hash</label><input id="landingHash" placeholder="/"></div>
              </div>
              <div class="field" style="margin-top:12px">
                <label for="customHeadersText">自定义请求头</label>
                <textarea id="customHeadersText" placeholder="Authorization: Basic YWRtaW46cGFzc3dvcmQK&#10;X-Custom-Header: value" style="min-height:80px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px"></textarea>
                <div class="hint">每行一个请求头，格式：Header-Name: value</div>
              </div>
              <div class="switches compact-switches">
                <label class="switch"><span>启用代理</span><input id="enabled" type="checkbox" checked></label>
                <label class="switch"><span>WebSocket</span><input id="websocket" type="checkbox"></label>
                <label class="switch"><span>阻止常见攻击</span><input id="blockExploits" type="checkbox" checked></label>
              </div>
            </div>
          </details>
        </section>
        <section class="tab-panel rule-panel" data-panel="locations"><div class="section-heading"><div><h3>路径规则</h3><p>匹配指定路径时，转发到不同源站</p></div></div><div class="field"><label for="locationsText">规则</label><textarea id="locationsText" placeholder="/api = http://api.example.com:8080&#10;/assets = https://static.example.com:443"></textarea><div class="hint">每行一条：路径 = 源站</div></div></section>
        <section class="tab-panel rule-panel" data-panel="ssl"><div class="section-heading"><div><h3>HTTPS</h3><p>访客侧的 HTTPS 由 Cloudflare 处理</p></div></div><div class="switches compact-switches"><label class="switch"><span>强制 HTTPS</span><input id="forceHttps" type="checkbox" checked></label><label class="switch"><span>启用 HSTS</span><input id="hsts" type="checkbox"></label></div></section>
      </div>
      <div class="modal-foot"><button type="button" class="button button-secondary" id="cancelDialog">取消</button><button type="submit" class="button button-primary">保存代理服务</button></div>
    </form>
  </dialog>
  
  <dialog id="passwordDialog" class="dialog-sm">
    <form id="passwordForm" class="modal-form">
      <div class="modal-head"><div class="modal-title"><span class="modal-title-mark"><svg class="icon" viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg></span><h2>修改密码</h2></div><button type="button" class="close-button" id="closePasswordDialog" aria-label="关闭"><svg class="icon" viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg></button></div>
      <div class="modal-body password-body">
        <div class="field">
          <label for="currentPassword">当前密码</label>
          <input id="currentPassword" type="password" autocomplete="current-password" required placeholder="请输入当前密码">
        </div>
        <div class="field">
          <label for="newPassword">新密码</label>
          <input id="newPassword" type="password" autocomplete="new-password" minlength="8" required placeholder="至少 8 位">
        </div>
        <div class="field">
          <label for="confirmPassword">确认新密码</label>
          <input id="confirmPassword" type="password" autocomplete="new-password" minlength="8" required placeholder="再次输入新密码">
        </div>
      </div>
      <div class="modal-foot password-foot">
        <button type="button" class="button button-secondary" id="cancelPasswordDialog">取消</button>
        <button type="submit" class="button button-primary">保存</button>
      </div>
    </form>
  </dialog>

  <div class="toast" id="toast"></div>
  <script nonce="{{NONCE}}">
    const state = { proxies: [], certificates: [], cf: { configured: false, tokens: [], zones: [], loading: false } };
    const editor = document.getElementById("editor");
    const form = document.getElementById("proxyForm");
    const fields = Object.fromEntries([
      "originalDomain","originUrl","domain","scheme","targetHost","targetPort","landingPath","landingHash","locationsText","customHeadersText","enabled","websocket","blockExploits","forceHttps","hsts"
    ].map(id => [id, document.getElementById(id)]));

    
    const passwordDialog = document.getElementById("passwordDialog");
    const passwordForm = document.getElementById("passwordForm");

    function openPasswordDialog() {
      if (!passwordForm || !passwordDialog) return;
      passwordForm.reset();
      document.querySelectorAll(".account-menu[open]").forEach((menu) => menu.removeAttribute("open"));
      if (typeof passwordDialog.showModal === "function") passwordDialog.showModal();
      else passwordDialog.setAttribute("open", "");
      document.getElementById("currentPassword")?.focus();
    }

    function closePasswordDialog() {
      if (!passwordDialog) return;
      if (typeof passwordDialog.close === "function") passwordDialog.close();
      else passwordDialog.removeAttribute("open");
    }


    function certBadge(status, text) {
      const span = document.createElement("span");
      const key = String(status || "unknown");
      span.className = "cert-badge " + key;
      span.textContent = text || key;
      return span;
    }

    function formatExpiry(item) {
      if (item.expiresOn) {
        const date = new Date(item.expiresOn);
        if (!Number.isNaN(date.getTime())) {
          const dateText = date.toLocaleDateString();
          if (item.daysLeft != null) {
            if (item.daysLeft < 0) return dateText + "（已过期）";
            return dateText + "（" + item.daysLeft + " 天）";
          }
          return dateText;
        }
      }
      if (item.autoRenew) return "自动续签中";
      return "—";
    }

    function renderCertificates() {
      const rows = document.getElementById("certRows");
      const table = document.getElementById("certTableWrap");
      const empty = document.getElementById("certEmpty");
      const emptyText = document.getElementById("certEmptyText");
      const badge = document.getElementById("certCfBadge");
      if (!rows || !table || !empty) return;

      const list = state.certificates || [];
      const active = list.filter((item) => item.status === "active").length;
      const pending = list.filter((item) => item.status === "pending" || item.status === "limited").length;
      const issues = list.filter((item) => ["warning", "unmanaged", "error", "unknown"].includes(item.status)).length;

      const setText = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = String(value);
      };
      setText("certActiveCount", active);
      setText("certPendingCount", pending);
      setText("certIssueCount", issues);
      setText("certTotalCount", list.length);

      if (badge) {
        if (!state.cf.configured) {
          badge.textContent = "未绑定 API";
          badge.className = "cf-status";
        } else {
          badge.textContent = (state.cf.tokens?.length || 0) + " 令牌 · 自动续签";
          badge.className = "cf-status on";
        }
      }

      rows.replaceChildren();
      if (!list.length) {
        table.hidden = true;
        empty.hidden = false;
        if (emptyText) {
          emptyText.textContent = state.cf.configured
            ? "添加代理后显示证书状态"
            : "绑定 Cloudflare API 并添加代理后显示";
        }
        return;
      }

      empty.hidden = true;
      table.hidden = false;
      for (const item of list) {
        const tr = document.createElement("tr");

        const domain = document.createElement("td");
        const domainLink = document.createElement("a");
        domainLink.className = "domain-link";
        domainLink.href = "https://" + item.domain;
        domainLink.target = "_blank";
        domainLink.rel = "noopener noreferrer";
        domainLink.textContent = "https://" + item.domain;
        domain.append(domainLink);

        const zone = document.createElement("td");
        zone.textContent = item.zone || "—";

        const status = document.createElement("td");
        status.append(certBadge(item.status, item.statusText || item.status));

        const expiry = document.createElement("td");
        expiry.className = "cert-mono";
        if (item.daysLeft != null && item.daysLeft <= 14 && item.daysLeft >= 0) {
          expiry.className += " cert-expiry-warn";
        }
        expiry.textContent = formatExpiry(item);

        const renew = document.createElement("td");
        if (item.autoRenew === true) {
          renew.className = "cert-renew-yes";
          renew.textContent = "是";
        } else if (item.autoRenew === false) {
          renew.className = "cert-renew-no";
          renew.textContent = "否";
        } else {
          renew.textContent = "—";
        }

        const mode = document.createElement("td");
        mode.className = "cert-mono";
        mode.textContent = item.sslMode || "—";

        const origin = document.createElement("td");
        origin.className = "cert-mono";
        origin.textContent = item.origin || "—";

        tr.append(domain, zone, status, expiry, renew, mode, origin);
        rows.append(tr);
      }
    }

async function loadCertificates(silent = false) {
      try {
        const data = await requestJson("/api/certificates");
        state.certificates = data.certificates || [];
        if (typeof data.configured === "boolean") {
          state.cf.configured = data.configured;
        }
        if (data.tokenCount != null && !state.cf.tokens?.length && data.configured) {
          // tokens details come from settings endpoint
        }
        renderCertificates();
        updateCloudflareGate();
        if (!silent && data.error) showToast(data.error, true);
      } catch (error) {
        if (!silent) showToast(error.message, true);
        renderCertificates();
      }
    }

function showToast(message, error = false) {
      const toast = document.getElementById("toast");
      toast.textContent = message;
      toast.className = "toast show" + (error ? " error" : "");
      setTimeout(() => toast.className = "toast", 2800);
    }

    function renderCfStatus() {
      const badge = document.getElementById("cfStatusBadge");
      const meta = document.getElementById("cfMeta");
      const tokenList = document.getElementById("cfTokenList");
      const zoneList = document.getElementById("cfZoneList");
      if (!badge || !meta) return;

      const tokens = state.cf.tokens || [];
      const zones = state.cf.zones || [];
      if (tokens.length) {
        badge.textContent = tokens.length + " 个令牌";
        badge.className = "cf-status on";
        meta.textContent = zones.length + " 个托管域名";
      } else {
        badge.textContent = "未绑定";
        badge.className = "cf-status";
        meta.textContent = "未绑定";
      }

      if (tokenList) {
        tokenList.replaceChildren();
        for (const token of tokens) {
          const row = document.createElement("div");
          row.className = "cf-token-item";
          const metaBox = document.createElement("div");
          metaBox.className = "meta";
          const name = document.createElement("div");
          name.className = "name";
          name.textContent = token.name || token.accountName || "Cloudflare";
          const sub = document.createElement("div");
          sub.className = "sub";
          const parts = [];
          if (token.accountName) parts.push(token.accountName);
          if (token.maskedToken) parts.push(token.maskedToken);
          if (token.zoneCount != null) parts.push(token.zoneCount + " 域名");
          sub.textContent = parts.join(" · ") || token.id;
          metaBox.append(name, sub);
          const actions = document.createElement("div");
          actions.className = "actions";
          const del = document.createElement("button");
          del.type = "button";
          del.className = "button button-danger button-sm";
          del.textContent = "删除";
          del.addEventListener("click", () => removeCloudflareToken(token.id));
          actions.append(del);
          row.append(metaBox, actions);
          tokenList.append(row);
        }
      }

      if (zoneList) {
        zoneList.replaceChildren();
        for (const zone of zones) {
          const chip = document.createElement("button");
          chip.type = "button";
          chip.className = "zone-chip-btn";
          chip.textContent = zone.name;
          chip.title = "填入 api." + zone.name;
          chip.addEventListener("click", () => {
            fields.domain.value = "api." + zone.name;
            fields.domain.focus();
            navigateTo("proxies");
            openEditor();
          });
          zoneList.append(chip);
        }
      }
    }

    function renderDomainSuggestions() {
      const datalist = document.getElementById("cfDomainSuggestions");
      const chips = document.getElementById("zoneChips");
      const hint = document.getElementById("domainHint");
      if (!datalist || !chips) return;
      datalist.replaceChildren();
      chips.replaceChildren();
      const zones = state.cf.zones || [];
      if (!state.cf.configured) {
        if (hint) hint.textContent = "请先绑定 Cloudflare API";
        return;
      }
      if (hint) hint.textContent = zones.length + " 个可用域名";
      for (const zone of zones) {
        for (const value of [zone.name, "api." + zone.name, "www." + zone.name]) {
          const opt = document.createElement("option");
          opt.value = value;
          datalist.append(opt);
        }
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "zone-chip-btn";
        chip.textContent = zone.name;
        chip.addEventListener("click", () => {
          const current = fields.domain.value.trim();
          if (!current || current.endsWith("." + zone.name) || current === zone.name) {
            fields.domain.value = current && current !== zone.name ? current : "api." + zone.name;
          } else if (!current.includes(".")) {
            fields.domain.value = current + "." + zone.name;
          } else {
            fields.domain.value = "api." + zone.name;
          }
          fields.domain.focus();
        });
        chips.append(chip);
      }
    }

    async function loadCloudflareSettings() {
      try {
        const data = await requestJson("/api/settings/cloudflare");
        state.cf.configured = Boolean(data.configured);
        state.cf.tokens = data.tokens || [];
        renderCfStatus();
        if (data.configured) {
          await loadCloudflareZones(true);
        } else {
          state.cf.zones = [];
          renderDomainSuggestions();
          renderCfStatus();
          updateCloudflareGate();
        }
      } catch (error) {
        renderCfStatus();
      }
    }

    async function loadCloudflareZones(silent = false) {
      if (state.cf.loading) return;
      state.cf.loading = true;
      try {
        const data = await requestJson("/api/cloudflare/zones");
        state.cf.configured = true;
        state.cf.zones = data.zones || [];
        if (data.tokenCount != null) {
          // keep tokens list; zone refresh shouldn't wipe it
        }
        renderCfStatus();
        renderDomainSuggestions();
        updateCloudflareGate();
        if (!silent) showToast("已刷新 " + state.cf.zones.length + " 个域名");
      } catch (error) {
        if (String(error.message || "").includes("未绑定")) {
          state.cf.configured = false;
          state.cf.zones = [];
          state.cf.tokens = [];
          renderCfStatus();
          renderDomainSuggestions();
          updateCloudflareGate();
        }
        if (!silent) showToast(error.message, true);
      } finally {
        state.cf.loading = false;
      }
    }

    async function saveCloudflareToken() {
      const apiToken = document.getElementById("cfApiToken").value.trim();
      const name = (document.getElementById("cfTokenName")?.value || "").trim();
      if (!apiToken) {
        showToast("请先粘贴 API 令牌", true);
        return;
      }
      try {
        const data = await requestJson("/api/settings/cloudflare", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ apiToken, name }),
        });
        document.getElementById("cfApiToken").value = "";
        if (document.getElementById("cfTokenName")) document.getElementById("cfTokenName").value = "";
        state.cf.configured = Boolean(data.configured);
        state.cf.tokens = data.tokens || [];
        state.cf.zones = data.zones || [];
        renderCfStatus();
        renderDomainSuggestions();
        updateCloudflareGate();
        showToast("已添加，共 " + (state.cf.tokens.length || 0) + " 个令牌");
      } catch (error) {
        showToast(error.message, true);
      }
    }

    async function removeCloudflareToken(tokenId) {
      if (!tokenId) {
        if (!confirm("确定删除全部 API 令牌？")) return;
      } else if (!confirm("确定删除该 API 令牌？")) {
        return;
      }
      try {
        const data = await requestJson(
          "/api/settings/cloudflare" + (tokenId ? ("?id=" + encodeURIComponent(tokenId)) : ""),
          { method: "DELETE" },
        );
        state.cf.configured = Boolean(data.configured);
        state.cf.tokens = data.tokens || [];
        if (!state.cf.configured) {
          state.cf.zones = [];
        } else {
          await loadCloudflareZones(true);
        }
        renderCfStatus();
        renderDomainSuggestions();
        updateCloudflareGate();
        showToast(state.cf.configured ? "令牌已删除" : "已解除全部绑定");
      } catch (error) {
        showToast(error.message, true);
      }
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
      document.querySelectorAll(".view").forEach((view) =>
        view.classList.toggle("active", view.dataset.view === name),
      );
      document.querySelectorAll("[data-view-link]").forEach((link) => {
        link.classList.toggle("active", link.dataset.viewLink === name);
      });
      document.querySelectorAll(".account-menu[open]").forEach((menu) => menu.removeAttribute("open"));
      if (name === "certificates") loadCertificates(true);
    }

    function navigateTo(name) {
      const target = ["dashboard", "proxies", "certificates", "settings"].includes(name)
        ? name
        : "dashboard";
      const current = location.hash.replace(/^#/, "") || "dashboard";
      if (current !== target) location.hash = target;
      showView(target);
    }

    function setTheme(theme) {
      document.documentElement.dataset.theme = theme;
      const toggle = document.getElementById("themeToggle");
      if (toggle) {
        toggle.setAttribute("aria-label", theme === "dark" ? "切换浅色模式" : "切换深色模式");
      }
      localStorage.setItem("edge-proxy-theme", theme);
    }

    function formatLocations(config) {
      return (config.locations || [])
        .map((item) => item.path + " = " + item.origin)
        .join("\\n");
    }

    function formatCustomHeaders(headers) {
      return (headers || [])
        .map((item) => item.name + ": " + item.value)
        .join("\\n");
    }

    function closeEditor() {
      if (typeof editor.close === "function") editor.close();
      else editor.removeAttribute("open");
    }

    function requireCloudflareBound(actionLabel = "操作") {
      if (!state.cf.configured) {
        showToast("请先绑定 Cloudflare API", true);
        navigateTo("settings");
        return false;
      }
      return true;
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
        parsed = new URL(value.includes("://") ? value : "http://" + value);
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
      fields.originUrl.value =
        parsed.origin + (landingPath || "") + (parsed.search || "") + (parsed.hash || "");
      if (!options.silent) {
        const parts = [scheme.toUpperCase(), parsed.hostname + ":" + port];
        if (landingPath) parts.push(landingPath);
        if (landingHash) parts.push("#" + landingHash);
        showToast("已解析：" + parts.join(" · "));
      }
      return true;
    }

function openEditor(config = null) {
      if (!requireCloudflareBound(config ? "编辑代理映射" : "添加代理映射")) return;
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
      fields.customHeadersText.value = config?.customHeaders ? formatCustomHeaders(config.customHeaders) : "";
      fields.enabled.checked = config ? config.enabled : true;
      fields.websocket.checked = config?.websocket || false;
      fields.blockExploits.checked = config ? config.blockExploits : true;
      fields.forceHttps.checked = config ? config.forceHttps : true;
      fields.hsts.checked = config?.hsts || false;
      document.getElementById("dialogTitle").textContent = config ? "编辑代理服务" : "添加代理服务";
      renderDomainSuggestions();
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
        title.textContent = "暂无代理";
        const description = document.createElement("p");
        description.textContent = "添加后显示在这里";
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
        const target = document.createElement("a");
        const targetUrl = config.scheme + "://" + config.targetHost + ":" + config.targetPort;
        target.className = "recent-target domain-link";
        target.href = targetUrl;
        target.target = "_blank";
        target.rel = "noopener noreferrer";
        target.textContent = targetUrl;
        target.title = "在新窗口打开 " + targetUrl;
        row.append(domain, target, createStatusBadge(config.enabled));
        recent.append(row);
      }
    }

    function updateCloudflareGate() {
      const enabled = Boolean(state.cf.configured);
      document.querySelectorAll(".open-editor, #headerAddProxy").forEach((btn) => {
        if (!btn) return;
        btn.disabled = !enabled;
        btn.title = enabled ? "" : "请先绑定 Cloudflare API 令牌";
        btn.classList.toggle("is-disabled", !enabled);
      });
      const hint = document.getElementById("domainHint");
      if (hint && !enabled) {
        hint.textContent = "请先绑定 Cloudflare API";
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
        const targetUrl = config.scheme + "://" + config.targetHost + ":" + config.targetPort;
        const targetLink = document.createElement("a");
        targetLink.className = "domain-link";
        targetLink.href = targetUrl;
        targetLink.target = "_blank";
        targetLink.rel = "noopener noreferrer";
        targetLink.textContent = targetUrl;
        targetLink.title = "在新窗口打开 " + targetUrl;
        target.append(targetLink);
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
        updateCloudflareGate();
        if ((location.hash.replace(/^#/, "") || "dashboard") === "certificates") loadCertificates(true);
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

    
    
    
    function positionAccountMenu() {
      const menu = document.querySelector(".account-menu");
      const dropdown = document.querySelector(".account-dropdown");
      const summary = menu?.querySelector("summary");
      if (!menu || !dropdown || !summary || !menu.open) return;
      const rect = summary.getBoundingClientRect();
      const width = dropdown.offsetWidth || 180;
      const top = Math.round(rect.bottom + 8);
      let left = Math.round(rect.right - width);
      left = Math.max(8, Math.min(left, window.innerWidth - width - 8));
      dropdown.style.top = top + "px";
      dropdown.style.left = left + "px";
      dropdown.style.right = "auto";
    }

    const accountMenu = document.querySelector(".account-menu");
    accountMenu?.addEventListener("toggle", () => {
      if (accountMenu.open) {
        positionAccountMenu();
        requestAnimationFrame(positionAccountMenu);
      }
    });
    window.addEventListener("resize", () => {
      if (accountMenu?.open) positionAccountMenu();
    });
    window.addEventListener("scroll", () => {
      if (accountMenu?.open) positionAccountMenu();
    }, true);


    document.getElementById("openPasswordDialog")?.addEventListener("click", (event) => {
      event.preventDefault();
      openPasswordDialog();
    });
    document.getElementById("closePasswordDialog")?.addEventListener("click", closePasswordDialog);
    document.getElementById("cancelPasswordDialog")?.addEventListener("click", closePasswordDialog);
    passwordDialog?.addEventListener("click", (event) => {
      if (event.target === passwordDialog) closePasswordDialog();
    });
    passwordForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const currentPassword = document.getElementById("currentPassword").value;
      const newPassword = document.getElementById("newPassword").value;
      const confirmPassword = document.getElementById("confirmPassword").value;
      try {
        await requestJson("/api/account/password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ currentPassword, newPassword, confirmPassword }),
        });
        closePasswordDialog();
        showToast("密码已更新");
      } catch (error) {
        showToast(error.message, true);
      }
    });

    
    document.getElementById("refreshCertificates")?.addEventListener("click", () => loadCertificates(false));

    document.getElementById("saveCfToken")?.addEventListener("click", saveCloudflareToken);
    document.getElementById("refreshCfZones")?.addEventListener("click", () => loadCloudflareZones(false));
    document.getElementById("removeCfToken")?.addEventListener("click", () => removeCloudflareToken());
    document.getElementById("reloadDomainSuggestions")?.addEventListener("click", () => loadCloudflareZones(false));

    document.getElementById("parseOriginUrl")?.addEventListener("click", () => parseOriginUrl(fields.originUrl.value));
    fields.originUrl?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        parseOriginUrl(fields.originUrl.value);
      }
    });
    fields.originUrl?.addEventListener("paste", () => {
      setTimeout(() => parseOriginUrl(fields.originUrl.value, { silent: true }), 0);
    });
    document.querySelectorAll(".open-editor").forEach(button => button.addEventListener("click", () => openEditor()));
    document.getElementById("closeDialog")?.addEventListener("click", closeEditor);
    document.getElementById("cancelDialog")?.addEventListener("click", closeEditor);
    document.querySelectorAll(".tab").forEach(tab => tab.addEventListener("click", () => selectTab(tab.dataset.tab)));
    document.getElementById("themeToggle")?.addEventListener("click", () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark"));
    
    // Event delegation: more reliable than per-link hover menus
    document.addEventListener("click", (event) => {
      const link = event.target.closest("[data-view-link]");
      if (!link) return;
      event.preventDefault();
      navigateTo(link.dataset.viewLink);
    });

    window.addEventListener("hashchange", () => showView(currentView()));
    fields.scheme?.addEventListener("change", () => {
      if (fields.targetPort.value === "80" || fields.targetPort.value === "443") fields.targetPort.value = fields.scheme.value === "https" ? "443" : "80";
    });
    editor?.addEventListener("click", event => {
      if (event.target === editor) closeEditor();
    });

    form?.addEventListener("submit", async event => {
      event.preventDefault();
      if (!requireCloudflareBound("保存代理映射")) return;
      const payload = {
        originalDomain: fields.originalDomain.value,
        domain: fields.domain.value,
        scheme: fields.scheme.value,
        targetHost: fields.targetHost.value,
        targetPort: Number(fields.targetPort.value),
        landingPath: fields.landingPath.value,
        landingHash: fields.landingHash.value,
        locationsText: fields.locationsText.value,
        customHeadersText: fields.customHeadersText.value,
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
    loadCloudflareSettings();
    updateCloudflareGate();
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
