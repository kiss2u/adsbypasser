#!/usr/bin/env node

/**
 * CI Domain Checker (refactored with debug)
 *
 * Features:
 *  - DNS resolution (IPv4/IPv6)
 *  - HTTP/HTTPS accessibility
 *  - SSL/TLS validation
 *  - Redirect loop detection
 *  - Timeout handling
 *  - Placeholder / parked page detection
 *  - Cloudflare / WAF / 5xx error detection
 *  - Blank or JS-only page detection (including redirect scripts)
 *  - Clear summary with status icons
 *  - Debug mode
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

/**
 * Debug logger
 */
function logDebug(message) {
  if (DEBUG) console.log(`[DEBUG] ${message}`);
}

/**
 * Check if a domain is resolvable via DNS (IPv4/IPv6)
 */
async function isDomainResolvable(domain) {
  try {
    await dns.resolve4(domain);
    logDebug(`Domain ${domain} resolved via IPv4`);
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      logDebug(`Domain ${domain} resolved via IPv6`);
      return true;
    } catch {
      logDebug(`Domain ${domain} is NOT resolvable`);
      return false;
    }
  }
}

/**
 * Fetch a URL with timeout and return status, headers, and body
 */
async function fetchUrl(url, timeoutMs = REQUEST_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === "https:" ? https : http;

    const timer = setTimeout(() => {
      logDebug(`Request to ${url} timed out`);
      resolve({ status: "TIMEOUT" });
    }, timeoutMs);

    const req = client.get(urlObj, (res) => {
      clearTimeout(timer);
      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 8192) body += chunk.toString();
      });
      res.on("end", () => {
        logDebug(`Fetched ${url}: ${res.statusCode}`);
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });

    req.on("error", (err) => {
      clearTimeout(timer);
      logDebug(`Error fetching ${url}: ${err.code}`);
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

/**
 * Determine if a page is blank or only contains JS
 */
function isEmptyOrJsOnly(body) {
  if (!body) return "EMPTY_PAGE";

  const stripped = body
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, "")
    .replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "")
    .replace(/\s/g, "");

  const scriptMatches = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
  const scriptContent = scriptMatches.map((m) => m[1]).join("").trim();

  if (stripped === "" && scriptContent) return "JS_ONLY";
  if (stripped.length === 0) return "EMPTY_PAGE";

  return false;
}

/* ------------------------ DOMAIN CHECK ------------------------ */

/**
 * Check if a domain is accessible and determine status
 */
async function checkDomainStatus(domain) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    try {
      let url = `${protocol}://${domain}`;
      const visited = new Set();
      let redirects = 0;

      while (redirects < MAX_REDIRECTS) {
        if (visited.has(url)) return "REDIRECT_LOOP";
        visited.add(url);

        const { status, statusCode, headers, body } = await fetchUrl(url);

        if (status) return status; // Low-level errors

        // Handle redirects
        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          url = new URL(headers.location, url).toString();
          logDebug(`Redirected to ${url}`);
          redirects++;
          continue;
        }

        // HTTP errors
        if (statusCode >= 500) return "SERVER_ERROR";
        if (statusCode >= 400) return "CLIENT_ERROR";

        if (body) {
          const emptyCheck = isEmptyOrJsOnly(body);
          if (emptyCheck) return emptyCheck;

          // Cloudflare / WAF / 5xx
          if (body.includes('id="cf-wrapper"') && body.includes('id="cf-error-details"')) {
            if (ERROR_PAGE_PATTERNS.some((p) => body.includes(p))) return "SERVER_ERROR";
            return "PROTECTED";
          }

          if (body.includes("Cloudflare Ray ID") || WAF_PATTERNS.some((p) => body.includes(p)))
            return "PROTECTED";

          // Placeholder
          if (PLACEHOLDER_PATTERNS.some((p) => body.includes(p))) return "PLACEHOLDER";
        }

        return "VALID";
      }

      return "REDIRECT_LOOP";
    } catch (err) {
      logDebug(`Exception checking ${protocol}://${domain}: ${err.message}`);
      continue;
    }
  }

  return "UNREACHABLE";
}

/**
 * Main domain check wrapper with DNS resolution
 */
async function checkDomain(domain) {
  const resolvable = await isDomainResolvable(domain);
  if (!resolvable) {
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

  try {
    const domains = await extractDomainsFromJSDoc(categories);
    const uniqueDomains = deduplicateRootDomains(domains);

    console.log(`Found ${uniqueDomains.length} unique root domains\n`);
    if (!uniqueDomains.length) return console.log("No domains found.");

    const results = [];
    for (const domain of uniqueDomains) {
      logDebug(`Checking domain: ${domain}`);
      const result = await checkDomain(domain);
      results.push(result);
      const icon = STATUS_ICONS[result.status] || "❓";
      console.log(`Checking ${domain}... ${icon} ${result.status}`);
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

    // Show problematic domains
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
