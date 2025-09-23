#!/usr/bin/env node

/**
 * CI Domain Checker (Updated)
 *
 * Features:
 *  - DNS resolution
 *  - HTTP/HTTPS accessibility
 *  - SSL/TLS validation
 *  - Redirect loop detection
 *  - Timeout handling
 *  - Placeholder / parked page detection
 *  - Cloudflare / WAF / 5xx error detection (including 521)
 *  - Blank or JS-only page detection
 *  - Clear summary with status icons
 *  - Debug logging
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

// Toggle debug logging
const DEBUG = true;
function logDebug(...args) {
  if (DEBUG) console.log("[DEBUG]", ...args);
}

/* ------------------------ UTILITIES ------------------------ */

// Check if a domain resolves via DNS
async function isDomainResolvable(domain) {
  try {
    await dns.resolve4(domain);
    logDebug(domain, "resolved via IPv4");
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      logDebug(domain, "resolved via IPv6");
      return true;
    } catch {
      logDebug(domain, "DNS resolution failed");
      return false;
    }
  }
}

// Fetch URL with timeout and return status, headers, body
async function fetchUrl(url, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === "https:" ? https : http;

    const timer = setTimeout(() => resolve({ status: "TIMEOUT" }), timeoutMs);

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
      if (
        err.code === "ECONNREFUSED" ||
        err.code === "ENOTFOUND" ||
        err.code === "EHOSTUNREACH"
      ) resolve({ status: "REFUSED" });
      else if (err.code === "CERT_HAS_EXPIRED" || err.code === "DEPTH_ZERO_SELF_SIGNED_CERT")
        resolve({ status: "INVALID_SSL" });
      else resolve({ status: "UNREACHABLE" });
    });
  });
}

// Detect empty or JS-only page
function isEmptyOrJsOnly(body) {
  if (!body) return "EMPTY_PAGE";

  const stripped = body
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, "")
    .replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "")
    .replace(/\s/g, "");

  const scriptMatches = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
  const scriptContent = scriptMatches.map((m) => m[1]).join("").trim();

  if (stripped === "" && scriptContent) return "JS_ONLY";

  return stripped.length === 0 ? "EMPTY_PAGE" : false;
}

/* ------------------------ DOMAIN CHECK ------------------------ */

async function checkDomainStatus(domain) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    try {
      let url = `${protocol}://${domain}`;
      const visited = new Set();
      let redirects = 0;

      while (redirects < MAX_REDIRECTS) {
        logDebug("Fetching URL:", url);
        if (visited.has(url)) return "REDIRECT_LOOP";
        visited.add(url);

        const { status, statusCode, headers, body } = await fetchUrl(url);

        if (status) {
          logDebug("Network error:", status);
          return status;
        }

        logDebug("Status code:", statusCode);

        // Explicit Cloudflare 5xx detection
        if ([521, 522, 523, 524, 525].includes(statusCode)) {
          logDebug("Cloudflare 5xx detected");
          return "SERVER_ERROR";
        }

        // Handle redirects
        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          logDebug("Redirect to:", headers.location);
          url = new URL(headers.location, url).toString();
          redirects++;
          continue;
        }

        // HTTP errors
        if (statusCode >= 500) return "SERVER_ERROR";
        if (statusCode >= 400) return "CLIENT_ERROR";

        if (body) {
          // Cloudflare / WAF detection
          if (
            body.toLowerCase().includes("cloudflare") &&
            ERROR_PAGE_PATTERNS.some((p) => body.includes(p))
          ) return "SERVER_ERROR";

          if (
            body.toLowerCase().includes("cloudflare") ||
            WAF_PATTERNS.some((p) => body.includes(p))
          ) return "PROTECTED";

          // Placeholder detection
          if (PLACEHOLDER_PATTERNS.some((p) => body.includes(p))) return "PLACEHOLDER";

          // Empty / JS-only page
          const emptyCheck = isEmptyOrJsOnly(body);
          if (emptyCheck) return emptyCheck;
        }

        return "VALID";
      }

      return "REDIRECT_LOOP";
    } catch (err) {
      logDebug("Exception:", err.message);
      continue;
    }
  }

  return "UNREACHABLE";
}

// Wrapper to check DNS first
async function checkDomain(domain) {
  const resolvable = await isDomainResolvable(domain);
  if (!resolvable) return { domain, status: "EXPIRED", resolvable: false, accessible: false };

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

    // Problematic domains
    const problematic = results.filter((r) => r.status !== "VALID");
    problematic.forEach((r) => {
      console.log(`${STATUS_ICONS[r.status] || "❓"} ${r.status} -> ${r.domain}`);
    });

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
