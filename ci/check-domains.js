#!/usr/bin/env node

/**
 * CI Domain Checker
 *
 * Features:
 *  - DNS resolution
 *  - HTTP/HTTPS accessibility
 *  - SSL/TLS validation
 *  - Redirect loop detection
 *  - Timeout handling
 *  - Placeholder / parked page detection
 *  - Cloudflare / WAF / 5xx error detection
 *  - Blank or JS-only page detection (including JS redirect scripts)
 *  - Clear summary with status icons
 */

import { extractDomainsFromJSDoc } from "../build/jsdoc.js";
import { deduplicateRootDomains } from "../build/domain.js";
import dns from "dns/promises";
import http from "http";
import https from "https";
import { URL } from "url";

/* ------------------------ CONFIG ------------------------ */

const MAX_REDIRECTS = 5; // Max redirect hops before assuming loop
const REQUEST_TIMEOUT_MS = 10000; // HTTP request timeout

// Patterns to detect placeholder / parked domains
const PLACEHOLDER_PATTERNS = [
  "Welcome to nginx!",
  "This domain is parked",
  "Buy this domain",
  "Domain for sale",
  "Default PLESK Page",
];

// Patterns to detect Cloudflare WAF / browser checks
const WAF_PATTERNS = [
  "Attention Required! | Cloudflare",
  "Checking your browser before accessing",
  "DDOS protection by",
];

// Patterns to detect Cloudflare / server 5xx error pages
const ERROR_PAGE_PATTERNS = [
  "Error 521",
  "Error 522",
  "Error 523",
  "Error 524",
  "Error 525",
  "Service Temporarily Unavailable",
];

// Status icons for console output
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
 * Check if a domain is resolvable via DNS (IPv4/IPv6)
 */
async function isDomainResolvable(domain) {
  try {
    await dns.resolve4(domain);
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      return true;
    } catch {
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

    const timer = setTimeout(() => resolve({ status: "TIMEOUT" }), timeoutMs);

    const req = client.get(urlObj, (res) => {
      clearTimeout(timer);
      let body = "";

      // Collect only first 8KB for detection
      res.on("data", (chunk) => {
        if (body.length < 8192) body += chunk.toString();
      });

      res.on("end", () =>
        resolve({ statusCode: res.statusCode, headers: res.headers, body })
      );
    });

    req.on("error", (err) => {
      clearTimeout(timer);

      if (["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH"].includes(err.code))
        resolve({ status: "REFUSED" });
      else if (["CERT_HAS_EXPIRED", "DEPTH_ZERO_SELF_SIGNED_CERT"].includes(err.code))
        resolve({ status: "INVALID_SSL" });
      else resolve({ status: "UNREACHABLE" });
    });
  });
}

/**
 * Determine if a page is blank or contains only JavaScript
 */
function isEmptyOrJsOnly(body) {
  if (!body) return true;

  // Remove <head> and <noscript> content + all whitespace
  let stripped = body
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, "")
    .replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "")
    .replace(/\s/g, "");

  // Extract all <script> content
  const scriptMatches = [...body.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)];
  const scriptContent = scriptMatches.map((m) => m[1]).join("").trim();

  // JS-only redirect / blank page
  if (stripped === "" && scriptContent) return "JS_ONLY";

  return stripped.length === 0 ? "EMPTY_PAGE" : false;
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

        if (status) return status; // Timeout, SSL, refused, unreachable

        // Handle HTTP redirects
        if (statusCode >= 300 && statusCode < 400 && headers.location) {
          url = new URL(headers.location, url).toString();
          redirects++;
          continue;
        }

        // HTTP errors
        if (statusCode >= 500) return "SERVER_ERROR";
        if (statusCode >= 400) return "CLIENT_ERROR";

        if (body) {
          // Detect empty or JS-only page
          const emptyCheck = isEmptyOrJsOnly(body);
          if (emptyCheck) return emptyCheck;

          // Detect Cloudflare / WAF
          if (body.includes('id="cf-wrapper"') && body.includes('id="cf-error-details"')) {
            if (ERROR_PAGE_PATTERNS.some((p) => body.includes(p))) return "SERVER_ERROR";
            return "PROTECTED";
          }

          if (body.includes("Cloudflare Ray ID") || WAF_PATTERNS.some((p) => body.includes(p)))
            return "PROTECTED";

          // Detect placeholder page
          if (PLACEHOLDER_PATTERNS.some((p) => body.includes(p))) return "PLACEHOLDER";
        }

        return "VALID";
      }

      return "REDIRECT_LOOP";
    } catch {
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

    // SUMMARY
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
