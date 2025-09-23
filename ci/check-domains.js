#!/usr/bin/env node

/**
 * Next-Level Domain Checker for CI
 *
 * This script extracts domains from src/sites/**.js using JSDoc metadata,
 * checks whether they are valid, accessible, or problematic, and prints
 * a detailed summary with icons.
 *
 * Features:
 * - DNS resolution check
 * - HTTP/HTTPS access check
 * - SSL/TLS validation
 * - Redirect loop detection
 * - Empty page / placeholder detection
 * - Cloudflare/WAF interstitial detection
 * - Differentiates TCP connection refused vs timeout
 * - Provides per-domain and summary reporting
 */

import { extractDomainsFromJSDoc } from "../build/jsdoc.js";
import { deduplicateRootDomains } from "../build/domain.js";
import dns from "dns/promises";
import https from "https";
import http from "http";
import { URL } from "url";

/** Patterns indicating parked / placeholder pages */
const BAD_PATTERNS = [
  "Welcome to nginx!",
  "This domain is parked",
  "Buy this domain",
  "Domain for sale",
  "Default PLESK Page",
];

/** Patterns indicating Cloudflare/WAF interstitial pages */
const WAF_PATTERNS = [
  "Attention Required! | Cloudflare",
  "Checking your browser before accessing",
  "DDOS protection by",
];

/** Status → Icon mapping */
const STATUS_ICONS = {
  VALID: "✅",
  PLACEHOLDER: "⚠️",
  EMPTY_PAGE: "📄",
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

/** Maximum number of redirects to follow before considering a loop */
const MAX_REDIRECTS = 5;

/**
 * Checks if a domain resolves via DNS (IPv4 or IPv6)
 * @param {string} domain
 * @returns {Promise<boolean>}
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
 * Checks if the domain is accessible via HTTP/HTTPS and returns status
 * @param {string} domain
 * @returns {Promise<string>} Status string (VALID, PLACEHOLDER, EMPTY_PAGE, SERVER_ERROR, etc.)
 */
async function isDomainAccessible(domain) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    try {
      let url = `${protocol}://${domain}`;
      const visited = new Set();
      let redirects = 0;

      while (redirects < MAX_REDIRECTS) {
        if (visited.has(url)) return "REDIRECT_LOOP";
        visited.add(url);

        const urlObj = new URL(url);
        const isHttps = protocol === "https";
        const client = isHttps ? https : http;

        const result = await new Promise((resolve) => {
          const req = client.request(
            {
              hostname: urlObj.hostname,
              port: urlObj.port || (isHttps ? 443 : 80),
              path: urlObj.pathname || "/",
              method: "GET",
              timeout: 7000,
              headers: {
                "User-Agent": "Mozilla/5.0 (compatible; DomainChecker/3.0)",
              },
            },
            (res) => {
              let body = "";
              res.on("data", (chunk) => {
                if (body.length < 8192) body += chunk.toString();
              });
              res.on("end", () => {
                const { statusCode, headers } = res;

                // Handle redirects
                if (statusCode >= 300 && statusCode < 400 && headers.location) {
                  url = new URL(headers.location, url).toString();
                  redirects++;
                  return resolve("REDIRECT");
                }

                // HTTP errors
                if (statusCode >= 500) return resolve("SERVER_ERROR");
                if (statusCode >= 400) return resolve("CLIENT_ERROR");

                const strippedBody = body.replace(/\s/g, "");

                // Detect empty or placeholder pages
                if (strippedBody.length < 50) return resolve("EMPTY_PAGE");
                if (BAD_PATTERNS.some((p) => body.includes(p))) return resolve("PLACEHOLDER");
                if (WAF_PATTERNS.some((p) => body.includes(p))) return resolve("PROTECTED");

                // Everything else is valid
                return resolve("VALID");
              });
            }
          );

          req.on("error", (err) => {
            if (
              isHttps &&
              (err.code === "CERT_HAS_EXPIRED" || err.code === "DEPTH_ZERO_SELF_SIGNED_CERT")
            ) {
              resolve("INVALID_SSL");
            } else if (err.code === "ECONNREFUSED") {
              resolve("REFUSED");
            } else if (err.code === "ETIMEDOUT") {
              resolve("TIMEOUT");
            } else {
              resolve("UNREACHABLE");
            }
          });

          req.on("timeout", () => resolve("TIMEOUT"));
          req.end();
        });

        if (result === "REDIRECT") continue; // Follow redirect
        return result;
      }

      return "REDIRECT_LOOP"; // Exceeded max redirects
    } catch {
      continue; // Try next protocol
    }
  }

  return "UNREACHABLE";
}

/**
 * Performs full check for a single domain (DNS + accessibility)
 * @param {string} domain
 * @returns {Promise<{domain:string,status:string,resolvable:boolean,accessible:boolean}>}
 */
async function checkDomain(domain) {
  const resolvable = await isDomainResolvable(domain);

  if (!resolvable) {
    return { domain, status: "EXPIRED", resolvable: false, accessible: false };
  }

  const status = await isDomainAccessible(domain);

  return { domain, status, resolvable: true, accessible: status === "VALID" };
}

/**
 * Main function to extract domains, check each, and summarize results
 */
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

    const order = [
      "VALID",
      "PLACEHOLDER",
      "EMPTY_PAGE",
      "CLIENT_ERROR",
      "SERVER_ERROR",
      "PROTECTED",
      "INVALID_SSL",
      "EXPIRED",
      "REFUSED",
      "TIMEOUT",
      "REDIRECT_LOOP",
      "UNREACHABLE",
      "UNKNOWN",
    ];

    for (const status of order) {
      if (counts[status]) {
        console.log(`${STATUS_ICONS[status]} ${status}: ${counts[status]}`);
      }
    }

    console.log(`📊 Total: ${results.length}`);

    // Print domains per problem status
    const problemStatuses = order.filter((s) => s !== "VALID");
    for (const status of problemStatuses) {
      const badDomains = results.filter((r) => r.status === status).map((r) => r.domain);
      if (badDomains.length) {
        console.log(`\n${STATUS_ICONS[status]} ${status} DOMAINS:`);
        badDomains.forEach((d) => console.log(`  - ${d}`));
      }
    }

    const invalidCount = results.filter((r) => r.status !== "VALID").length;
    console.log(
      invalidCount ? `\n⚠️ Found ${invalidCount} problematic domain(s)` : "\n✅ All domains are valid!"
    );
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

// Execute main function
main().catch(console.error);
