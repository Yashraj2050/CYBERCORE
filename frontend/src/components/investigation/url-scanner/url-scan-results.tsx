"use client";

import * as React from "react";
import { ScanAssessmentHeader } from "./scan-assessment-header";
import { ScanComponentCard } from "./scan-component-card";
import { ScanTechnicalFindings } from "./scan-technical-findings";
import { RawResponseViewer } from "./raw-response-viewer";
import type { UrlScanResult } from "@/types/scanner";

interface UrlScanResultsProps {
  scan: UrlScanResult;
}

const SUBSYSTEM_DEFINITIONS = [
  {
    id: "phishing_malware",
    name: "Phishing & Malware Heuristics",
    description: "Pattern detection and signature telemetry for malicious vectors.",
  },
  {
    id: "url_patterns",
    name: "URL Syntax & Heuristic Patterns",
    description: "Lexical entropy, raw IP usage, and homoglyph detection.",
  },
  {
    id: "domain_reputation",
    name: "Domain Reputation & TLD Risk",
    description: "Domain authority, registrar trust, and historical blacklist records.",
  },
  {
    id: "ssl_tls",
    name: "SSL / TLS Encryption Integrity",
    description: "Certificate validity, chain of trust, and cryptographic parameters.",
  },
  {
    id: "redirect_analysis",
    name: "Redirect & Cloaking Analysis",
    description: "Multi-hop redirection tracing and destination validation.",
  },
  {
    id: "threat_intelligence",
    name: "Threat Intelligence Feeds",
    description: "External feeds and collaborative indicator feeds (requires API key).",
  },
];

export function UrlScanResults({ scan }: UrlScanResultsProps) {
  const components = scan.components || {};

  return (
    <div className="space-y-8 animate-in fade-in-50 duration-300">
      {/* 1. Assessment Header & Score */}
      <ScanAssessmentHeader scan={scan} />

      {/* 2. Subsystem Inspection Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-2">
          <div className="flex items-center gap-2">
            <span className="h-1.5 w-1.5 bg-cyber-accent rounded-full" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              SUBSYSTEM THREAT ANALYSIS
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            6 INSPECTION VECTORS EVALUATED
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {SUBSYSTEM_DEFINITIONS.map((def) => (
            <ScanComponentCard
              key={def.id}
              id={def.id}
              name={def.name}
              description={def.description}
              detail={components[def.id]}
            />
          ))}
        </div>
      </div>

      {/* 3. DNS, WHOIS & Recommended Actions */}
      <ScanTechnicalFindings
        dns={scan.dns_details || {}}
        whois={scan.whois_details || {}}
        recommendedActions={scan.recommended_actions || []}
        domain={scan.domain}
      />

      {/* 4. Raw OpenAPI Telemetry */}
      <RawResponseViewer scan={scan} />
    </div>
  );
}

