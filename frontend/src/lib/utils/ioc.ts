/**
 * Indicator of Compromise (IOC) Detection Engine
 * Accurately classifies network and cryptographic indicators for the CYBERCORE Command Palette.
 */

export type IocType = "URL" | "IPv4" | "IPv6" | "Domain" | "MD5" | "SHA-1" | "SHA-256" | "CVE";

export interface IocMatch {
  type: IocType;
  query: string;
  label: string;
  description: string;
}

// Strict IPv4 regex enforcing 0-255 octet boundaries
const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/;

// RFC-compliant IPv6 regex supporting compressed, loopback, and standard forms
const IPV6_REGEX =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;

// Exact cryptographic hash signatures
const MD5_REGEX = /^[0-9a-fA-F]{32}$/;
const SHA1_REGEX = /^[0-9a-fA-F]{40}$/;
const SHA256_REGEX = /^[0-9a-fA-F]{64}$/;

// Standard CVE Identifier: CVE-YYYY-NNNN... (4+ sequence digits)
const CVE_REGEX = /^cve-\d{4}-\d{4,}$/i;

// RFC-compliant Domain pattern: no protocol, no double dots, valid TLD
const DOMAIN_REGEX =
  /^(?!:\/\/)(?![.-])(?!.*[.-]{2})(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;

/**
 * Evaluates a user query and returns structured IOC metadata if recognized.
 * Rejects ordinary sentences, URLs with protocols, and malformed identifiers.
 */
export function detectIoc(query: string): IocMatch | null {
  const q = query.trim();
  if (!q || q.length < 3) return null;

  // Strict URL detection
  if (q.startsWith("http://") || q.startsWith("https://")) {
    try {
      const parsed = new URL(q);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        return {
          type: "URL",
          query: q,
          label: `Target URL: ${q}`,
          description: "Execute synchronous heuristic scan, DNS topology, and SSL analysis",
        };
      }
    } catch {
      // not a valid URL
    }
  }

  if (IPV4_REGEX.test(q)) {
    return {
      type: "IPv4",
      query: q,
      label: `IPv4 Address: ${q}`,
      description: "Lookup IP routing, reverse DNS PTR, and reputation telemetry",
    };
  }

  if (IPV6_REGEX.test(q)) {
    return {
      type: "IPv6",
      query: q,
      label: `IPv6 Address: ${q}`,
      description: "Lookup IPv6 routing and entity intelligence",
    };
  }

  if (MD5_REGEX.test(q)) {
    return {
      type: "MD5",
      query: q.toLowerCase(),
      label: `MD5 Hash: ${q.toLowerCase()}`,
      description: "Query 32-character binary signature threat intelligence",
    };
  }

  if (SHA1_REGEX.test(q)) {
    return {
      type: "SHA-1",
      query: q.toLowerCase(),
      label: `SHA-1 Hash: ${q.toLowerCase()}`,
      description: "Query 40-character binary signature threat intelligence",
    };
  }

  if (SHA256_REGEX.test(q)) {
    return {
      type: "SHA-256",
      query: q.toLowerCase(),
      label: `SHA-256 Hash: ${q.toLowerCase()}`,
      description: "Query 64-character cryptographic threat signature",
    };
  }

  if (CVE_REGEX.test(q)) {
    const cveUpper = q.toUpperCase();
    return {
      type: "CVE",
      query: cveUpper,
      label: `Vulnerability: ${cveUpper}`,
      description: "Investigate vulnerability catalog and mitigation indicators",
    };
  }

  if (DOMAIN_REGEX.test(q)) {
    const domLower = q.toLowerCase();
    return {
      type: "Domain",
      query: domLower,
      label: `Domain: ${domLower}`,
      description: "Lookup DNS zone configuration, MX/NS records, and RDAP registration",
    };
  }

  return null;
}

