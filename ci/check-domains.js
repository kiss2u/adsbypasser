#!/usr/bin/env node

import dns from "dns/promises";
import http from "http";
import https from "https";
import { URL } from "url";
import { extractDomainsFromJSDoc } from "../build/jsdoc.js";
import { deduplicateRootDomains } from "../build/domain.js";

/* ------------------------ CONFIG ------------------------ */

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 10000;
const DEBUG = true;

const PLACEHOLDER_PATTERNS = [
  "Welcome to nginx!",
  "This domain is parked",
  "Buy this domain",
  "Domain for sale",
  "Default PLESK Page",
];

const WAF_PATTERNS = [
  "Attention Required! | Cloudflare",
  "Checking your browser before accessing",
  "DDOS protection by",
];

const ERROR_PAGE_PATTERNS = [
  "Error 521",
  "Error 522",
  "Error 523",
  "Error 524",
  "Error 525",
  "Service Temporarily Unavailable",
];

const STATUS_ICONS = {
  VALID: "✅",
  PLACEHOLDER: "⚠️",
  EMPTY_PAGE: "📄",
  JS_ONLY: "📜",
  CLIENT_ERROR: "🚫",
  SERVER_ERROR: "🔥",
  INVALID_SSL: "🔒",
  EXPIRED: "❌",
  UNREACHABLE: "🌐",
  REFUSED: "⛔",
  TIMEOUT: "⏱️",
  REDIRECT_LOOP: "🔁",
  PROTECTED: "🛡️",
  UNKNOWN: "❓",
};

/* ------------------------ UTILITIES ------------------------ */

function debugLog(...args) {
  if (DEBUG) console.log("[DEBUG]", ...args);
}

async function isDomainResolvable(domain) {
  try {
    await dns.resolve4(domain);
    debugLog(domain, "resolved via IPv4");
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      debugLog(domain, "resolved via IPv6");
      return true;
    } catch {
      debugLog(domain, "cannot resolve DNS");
      return false;
    }
  }
}

async function fetchUrl(url, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === "https:" ? https : http;

    const timer = setTimeout(() => {
      debugLog(url, "timeout");
      resolve({ status: "TIMEOUT" });
    }, timeoutMs);

    const req = client.get(urlObj, (res) => {
      clearTimeout(timer);
      let body = "";
      res.on("data", (chunk) => (body += chunk.toString()));
      res.on("end", () => {
        debugLog(url, "statusCode:", res.statusCode, "bodyLength:", body.length);
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });

    req.on("error", (err) => {
      clearTimeout(timer);
      debugLog(url, "error:", err.code);
      if (
        err.code === "ECONNREFUSED" ||
        err.code === "ENOTFOUND" ||
        err.code === "EHOSTUNREACH"
      )
        resolve({ status: "REFUSED" });
      else if (err.code === "CERT_HAS_EXPIRED" || err.code === "DEPTH_ZERO_SELF_SIGNED_CERT")
        resolve({ status: "INVALID_SSL" });
      else resolve({ status: "UNREACHABLE" });
    });
  });
}

/**
 * Enhanced detection of empty / JS-only / redirect pages
 */
function isEmptyOrJsOnly(body) {
  if (!body) return "EMPTY_PAGE";

  const stripped = body
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, "")
    .replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "")
    .replace(/\s/g, "");

  const scriptMatches = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
  const scriptContent = scriptMatches.map((m) => m[1]).join("").trim();

  const jsRedirectPatterns = [
    /window\.location\s*=/i,
    /document\.location\s*=/i,
    /location\.href\s*=/i,
    /document\.write\s*\(/i,
    /window\.onload\s*=\s*function/i,
  ];
  const hasJsRedirect = jsRedirectPatterns.some((rx) => rx.test(scriptContent));

  if (stripped === "" && scriptContent) {
    if (hasJsRedirect) return "JS_ONLY";
    return "EMPTY_PAGE";
  }

  return false;
}

/* ------------------------ DOMAIN CHECK ------------------------ */

async function checkDomainStatus(domain) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    let url = `${protocol}://${domain}`;
    const visited = new Set();
    let redirects = 0;

    while (redirects < MAX_REDIRECTS) {
      if (visited.has(url)) {
        debugLog(domain, "redirect loop detected");
        return "REDIRECT_LOOP";
      }
      visited.add(url);

      const { status, statusCode, headers, body } = await fetchUrl(url);
      if (status) return status;

      if (statusCode >= 300 && statusCode < 400 && headers.location) {
        url = new URL(headers.location, url).toString();
        debugLog(domain, "redirecting to", url);
        redirects++;
        continue;
      }

      if (statusCode >= 500) return "SERVER_ERROR";
      if (statusCode >= 400) return "CLIENT_ERROR";

      if (body) {
        const emptyCheck = isEmptyOrJsOnly(body);
        if (emptyCheck) {
          debugLog(domain, "empty/js-only detected:", emptyCheck);
          return emptyCheck;
        }

        if (body.includes('id="cf-wrapper"') && body.includes('id="cf-error-details"')) {
          if (ERROR_PAGE_PATTERNS.some((p) => body.includes(p))) {
            debugLog(domain, "Cloudflare error page detected");
            return "SERVER_ERROR";
          }
          return "PROTECTED";
        }

        if (body.includes("Cloudflare Ray ID") || WAF_PATTERNS.some((p) => body.includes(p))) {
          debugLog(domain, "WAF/Cloudflare protection detected");
          return "PROTECTED";
        }

        if (PLACEHOLDER_PATTERNS.some((p) => body.includes(p))) {
          debugLog(domain, "placeholder detected");
          return "PLACEHOLDER";
        }
      }

      return "VALID";
    }

    return "REDIRECT_LOOP";
  }

  return "UNREACHABLE";
}

async function checkDomain(domain) {
  const resolvable = await isDomainResolvable(domain);
  if (!resolvable)
    return { domain, status: "EXPIRED", resolvable: false, accessible: false };

  const status = await checkDomainStatus(domain);
  return { domain, status, resolvable: true, accessible: status === "VALID" };
}

/* ------------------------ MAIN ------------------------ */

async function main() {
  const args = process.argv.slice(2);
  const categories = args.length ? args : null;

  console.log("Extracting domains...");
  console.log(`Categories: ${categories ? categories.join(", ") : "all"}`);

  try {
    const domains = await extractDomainsFromJSDoc(categories);
    const uniqueDomains = deduplicateRootDomains(domains);

    console.log(`Found ${uniqueDomains.length} unique domains\n`);
    if (!uniqueDomains.length) return console.log("No domains found.");

    const results = [];
    for (const domain of uniqueDomains) {
      process.stdout.write(`Checking ${domain}... `);
      const result = await checkDomain(domain);
      results.push(result);
      const icon = STATUS_ICONS[result.status] || "❓";
      console.log(`${icon} ${result.status}`);
    }

    // ----------------- SUMMARY -----------------
    console.log("\n" + "=".repeat(50));
    console.log("SUMMARY:");

    const counts = results.reduce((acc, r) => {
      acc[r.status] = (acc[r.status] || 0) + 1;
      return acc;
    }, {});

    Object.keys(STATUS_ICONS).forEach((status) => {
      if (counts[status]) console.log(`${STATUS_ICONS[status]} ${status}: ${counts[status]}`);
    });

    console.log(`📊 Total domains checked: ${results.length}`);

    const problematic = results.filter((r) => r.status !== "VALID");
    problematic.forEach((r) => {
      console.log(`${STATUS_ICONS[r.status] || "❓"} ${r.status} -> ${r.domain}`);
    });

    // ----------------- DETAILED DEBUG SUMMARY -----------------
    if (DEBUG) {
      const categoriesSummary = {};
      problematic.forEach((r) => {
        categoriesSummary[r.status] = (categoriesSummary[r.status] || 0) + 1;
      });
      console.log("\n[DEBUG] Detailed problematic domain summary:");
      Object.keys(categoriesSummary).forEach((status) => {
        console.log(`[DEBUG] ${STATUS_ICONS[status] || "❓"} ${status}: ${categoriesSummary[status]}`);
      });
    }

    console.log(
      problematic.length
        ? `\n⚠️ Found ${problematic.length} problematic domain(s)`
        : "\n✅ All domains are valid!"
    );
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main().catch(console.error);
