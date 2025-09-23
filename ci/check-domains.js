#!/usr/bin/env node

/**
 * Enhanced domain checker - extracts domains from src/sites/**.js and reports validity
 */
import { extractDomainsFromJSDoc } from "../build/jsdoc.js";
import { deduplicateRootDomains } from "../build/domain.js";
import dns from "dns/promises";
import https from "https";
import http from "http";
import { URL } from "url";

/**
 * Common placeholder text patterns that indicate a parked/default site
 */
const BAD_PATTERNS = [
  "Welcome to nginx!",
  "This domain is parked",
  "Buy this domain",
  "Domain for sale",
  "Default PLESK Page",
];

/**
 * Status → Icon mapping
 */
const STATUS_ICONS = {
  VALID: "✅",
  PLACEHOLDER: "⚠️",
  CLIENT_ERROR: "🚫",
  SERVER_ERROR: "🔥",
  INVALID_SSL: "🔒",
  EXPIRED: "❌",
  UNREACHABLE: "🌐",
  UNKNOWN: "❓",
};

/**
 * Check if a domain is resolvable via DNS
 * @param {string} domain - Domain to check
 * @returns {Promise<boolean>} True if resolvable
 */
async function isDomainResolvable(domain) {
  try {
    // Try IPv4 first
    await dns.resolve4(domain);
    return true;
  } catch {
    try {
      // Try IPv6 if IPv4 fails
      await dns.resolve6(domain);
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Check if a domain is accessible via HTTP/HTTPS
 * @param {string} domain - Domain to check
 * @returns {Promise<string>} Status string
 */
async function isDomainAccessible(domain) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    try {
      const url = `${protocol}://${domain}`;
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
            timeout: 5000,
            headers: {
              "User-Agent": "Mozilla/5.0 (compatible; DomainChecker/1.1)",
            },
          },
          (res) => {
            let body = "";
            res.on("data", (chunk) => {
              if (body.length < 4096) body += chunk.toString();
            });
            res.on("end", () => {
              const { statusCode } = res;

              if (statusCode >= 200 && statusCode < 400) {
                const isPlaceholder = BAD_PATTERNS.some((p) =>
                  body.includes(p),
                );
                resolve(isPlaceholder ? "PLACEHOLDER" : "VALID");
              } else if (statusCode >= 400 && statusCode < 500) {
                resolve("CLIENT_ERROR");
              } else if (statusCode >= 500) {
                resolve("SERVER_ERROR");
              } else {
                resolve("UNKNOWN");
              }
            });
          },
        );

        req.on("error", (err) => {
          if (
            isHttps &&
            (err.code === "CERT_HAS_EXPIRED" ||
              err.code === "DEPTH_ZERO_SELF_SIGNED_CERT")
          ) {
            resolve("INVALID_SSL");
          } else {
            resolve("UNREACHABLE");
          }
        });
        req.on("timeout", () => resolve("UNREACHABLE"));
        req.end();
      });

      if (result !== "UNREACHABLE") return result;
    } catch {
      continue;
    }
  }

  return "UNREACHABLE";
}

/**
 * Check domain status
 * @param {string} domain - Domain to check
 * @returns {Promise<Object>} Status object
 */
async function checkDomain(domain) {
  const isResolvable = await isDomainResolvable(domain);

  if (!isResolvable) {
    return { domain, status: "EXPIRED", resolvable: false, accessible: false };
  }

  const status = await isDomainAccessible(domain);

  return {
    domain,
    status,
    resolvable: true,
    accessible: status === "VALID",
  };
}

/**
 * Main function
 */
async function main() {
  const args = process.argv.slice(2);
  const categories = args.length > 0 ? args : null;

  console.log("Extracting domains from sites directory...");
  if (categories) {
    console.log(`Categories: ${categories.join(", ")}`);
  } else {
    console.log("Categories: all");
  }

  try {
    // Extract domains from sites
    const domains = await extractDomainsFromJSDoc(categories);
    const uniqueDomains = deduplicateRootDomains(domains);

    console.log(`Found ${uniqueDomains.length} unique root domains\n`);

    if (uniqueDomains.length === 0) {
      console.log("No domains found.");
      return;
    }

    // Check each domain
    const results = [];
    for (const domain of uniqueDomains) {
      process.stdout.write(`Checking ${domain}... `);
      const result = await checkDomain(domain);
      results.push(result);

      const statusIcon = STATUS_ICONS[result.status] || "❓";
      console.log(`${statusIcon} ${result.status}`);
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
      "CLIENT_ERROR",
      "SERVER_ERROR",
      "INVALID_SSL",
      "EXPIRED",
      "UNREACHABLE",
      "UNKNOWN",
    ];

    for (const status of order) {
      if (counts[status]) {
        console.log(`${STATUS_ICONS[status]} ${status}: ${counts[status]}`);
      }
    }

    console.log(`📊 Total: ${results.length}`);

    // Show problematic domains
    const problemStatuses = order.filter((s) => s !== "VALID");
    for (const status of problemStatuses) {
      const badDomains = results
        .filter((r) => r.status === status)
        .map((r) => r.domain);

      if (badDomains.length > 0) {
        console.log(`\n${STATUS_ICONS[status]} ${status} DOMAINS:`);
        badDomains.forEach((d) => console.log(`  - ${d}`));
      }
    }

    const invalidCount = results.filter((r) => r.status !== "VALID").length;
    if (invalidCount > 0) {
      console.log(`\n⚠️ Found ${invalidCount} problematic domain(s)`);
    } else {
      console.log("\n✅ All domains are valid!");
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
}

// Execute main function directly
main().catch(console.error);
