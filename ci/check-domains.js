#!/usr/bin/env node

/**
 * CI Domain Checker (Refactored with Debug)
 *
 * Features:
 *  - DNS resolution
 *  - HTTP/HTTPS accessibility
 *  - SSL/TLS validation
 *  - Redirect loop detection
 *  - Timeout handling
 *  - Placeholder / parked page detection
 *  - Cloudflare / WAF / 5xx error detection
 *  - Blank or JS-only page detection
 *  - Clear debug logs and summary
 */

import { extractDomainsFromJSDoc } from "../build/jsdoc.js";
import { deduplicateRootDomains } from "../build/domain.js";
import dns from "dns/promises";
import http from "http";
import https from "https";
import { URL } from "url";

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

// Check if domain resolves via DNS
async function isDomainResolvable(domain) {
  try {
    await dns.resolve4(domain);
    if (DEBUG) console.log(`[DEBUG] DNS resolved IPv4: ${domain}`);
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      if (DEBUG) console.log(`[DEBUG] DNS resolved IPv6: ${domain}`);
      return true;
    } catch {
      if (DEBUG) console.log(`[DEBUG] DNS resolution failed: ${domain}`);
      return false;
    }
  }
}

// Fetch a URL with timeout and return status, headers, and body
async function fetchUrl(url, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === "https:" ? https : http;

    const timer = setTimeout(() => {
      if (DEBUG) console.log(`[DEBUG] Timeout: ${url}`);
      resolve({ status: "TIMEOUT" });
    }, timeoutMs);

    const req = client.get(urlObj, (res) => {
      clearTimeout(timer);
      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 8192) body += chunk.toString();
      });
      res.on("end", () =>
        resolve({ statusCode: res.statusCode, headers: res.headers, body })
      );
    });

    req.on("error", (err) => {
      clearTimeout(timer);
      if (DEBUG) console.log(`[DEBUG] Request error (${url}): ${err.code}`);
      if (["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH"].includes(err.code)) {
        resolve({ status: "REFUSED" });
      } else if (["CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT"].includes(err.code)) {
        resolve({ status: "INVALID_SSL" });
      } else {
        resolve({ status: "UNREACHABLE" });
      }
    });
  });
}

// Check if page is blank or JS-only
function isEmptyOrJsOnly(body) {
  if (!body) return "EMPTY_PAGE";

  // Remove head, noscript, whitespace
  let stripped = body
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, "")
    .replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "")
    .replace(/\s/g, "");

  // Extract script content
  const scriptMatches = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
  const scriptContent = scriptMatches.map((m) => m[1]).join("").trim();

  if (stripped === "" && scriptContent) return "JS_ONLY";
  if (stripped.length === 0) return "EMPTY_PAGE";

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
        if (DEBUG) console.log(`[DEBUG] Redirect loop detected: ${url}`);
        return "REDIRECT_LOOP";
      }
      visited.add(url);

      const { status, statusCode, headers, body } = await fetchUrl(url);

      if (status) {
        if (DEBUG) console.log(`[DEBUG] Low-level error for ${url}: ${status}`);
        return status;
      }

      if (statusCode >= 500) {
        if (DEBUG) console.log(`[DEBUG] Server error ${statusCode} for ${url}`);
        return "SERVER_ERROR";
      }
      if (statusCode >= 400) {
        if (DEBUG) console.log(`[DEBUG] Client error ${statusCode} for ${url}`);
        return "CLIENT_ERROR";
      }

      // Redirects
      if (statusCode >= 300 && statusCode < 400 && headers.location) {
        url = new URL(headers.location, url).toString();
        redirects++;
        if (DEBUG) console.log(`[DEBUG] Redirecting to ${url}`);
        continue;
      }

      // Detect placeholder / blank / JS-only
      const emptyCheck = isEmptyOrJsOnly(body);
      if (emptyCheck) {
        if (DEBUG) console.log(`[DEBUG] Empty/JS-only page for ${url}: ${emptyCheck}`);
        return emptyCheck;
      }

      // Detect Cloudflare / WAF
      if (body.includes('id="cf-wrapper"') && body.includes('id="cf-error-details"')) {
        if (ERROR_PAGE_PATTERNS.some((p) => body.includes(p))) {
          if (DEBUG) console.log(`[DEBUG] Cloudflare error page detected: ${url}`);
          return "SERVER_ERROR";
        } else {
          if (DEBUG) console.log(`[DEBUG] Cloudflare WAF page detected: ${url}`);
          return "PROTECTED";
        }
      }

      if (body.includes("Cloudflare Ray ID") || WAF_PATTERNS.some((p) => body.includes(p))) {
        if (DEBUG) console.log(`[DEBUG] Cloudflare WAF / protection detected: ${url}`);
        return "PROTECTED";
      }

      // Detect placeholder pages
      if (PLACEHOLDER_PATTERNS.some((p) => body.includes(p))) {
        if (DEBUG) console.log(`[DEBUG] Placeholder page detected: ${url}`);
        return "PLACEHOLDER";
      }

      if (DEBUG) console.log(`[DEBUG] Valid page detected: ${url}`);
      return "VALID";
    }

    if (DEBUG) console.log(`[DEBUG] Max redirects reached for ${url}`);
    return "REDIRECT_LOOP";
  }

  if (DEBUG) console.log(`[DEBUG] Domain unreachable: ${domain}`);
  return "UNREACHABLE";
}

async function checkDomain(domain) {
  const resolvable = await isDomainResolvable(domain);
  if (!resolvable) {
    if (DEBUG) console.log(`[DEBUG] Domain expired / unresolvable: ${domain}`);
    return { domain, status: "EXPIRED", resolvable: false, accessible: false };
  }

  const status = await checkDomainStatus(domain);
  return { domain, status, resolvable: true, accessible: status === "VALID" };
}

/* ------------------------ MAIN ------------------------ */

async function main() {
  const args = process.argv.slice(2);
  const categories = args.length ? args : null;

  console.log("Extracting domains from sites directory...");
  console.log(`Categories: ${categories ? categories.join(", ") : "all"}`);

  const domains = await extractDomainsFromJSDoc(categories);
  const uniqueDomains = deduplicateRootDomains(domains);

  console.log(`Found ${uniqueDomains.length} unique root domains\n`);
  if (!uniqueDomains.length) return console.log("No domains found.");

  const results = [];
  for (const domain of uniqueDomains) {
    process.stdout.write(`Checking ${domain}... `);
    const result = await checkDomain(domain);
    results.push(result);
    const icon = STATUS_ICONS[result.status] || "❓";
    console.log(`${icon} ${result.status}`);
  }

  // Summary
  console.log("\n" + "=".repeat(50));
  console.log("SUMMARY:");
  const counts = results.reduce((acc, r) => {
    acc[r.status] = (acc[r.status] || 0) + 1;
    return acc;
  }, {});

  Object.keys(STATUS_ICONS).forEach((status) => {
    if (counts[status]) console.log(`${STATUS_ICONS[status]} ${status}: ${counts[status]}`);
  });

  console.log(`📊 Total: ${results.length}`);

  const problematic = results.filter((r) => r.status !== "VALID");
  problematic.forEach((r) => {
    console.log(`${STATUS_ICONS[r.status] || "❓"} ${r.status} -> ${r.domain}`);
  });

  console.log(
    problematic.length
      ? `\n⚠️ Found ${problematic.length} problematic domain(s)`
      : "\n✅ All domains are valid!"
  );
}

main().catch(console.error);
