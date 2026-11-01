"use client";

import * as React from "react";
import Link from "next/link";
import {
  Globe,
  MessageSquare,
  Radio,
  FileSearch,
  Lock,
  ArrowRight,
  Shield,
  Terminal,
  ExternalLink,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { apiConfig } from "@/config/api";
import { PasswordChecker } from "@/components/investigation/password-checker";

const toolModules = [
  {
    id: "scanner",
    name: "Website URL Scanner",
    description:
      "Performs SSRF-validated, multi-stage inspection of suspicious URLs. Analyzes DNS configuration, SSL certificate validity, pattern heuristics, and threat intelligence database matches.",
    icon: Globe,
    method: "POST",
    endpoint: "/api/v1/scan/",
    payloadType: '{ "url": "https://example.com", "source": "web" }',
    rateLimit: "30 req/min per IP",
    status: "READY",
    href: "/security-tools/url-scanner",
  },
  {
    id: "message",
    name: "Message Phishing Analyzer",
    description:
      "Heuristic & pattern-based threat evaluation of SMS, email, and chat messages. Detects artificial urgency tactics, fake OTP verification requests, and banking impersonation patterns using deterministic rule matching.",
    icon: MessageSquare,
    method: "POST",
    endpoint: "/api/v1/messages/analyze",
    payloadType: '{ "message": "string", "source": "web" }',
    rateLimit: "Standard bus quota",
    status: "READY",
    href: "/security-tools/message-analyzer",
  },
  {
    id: "ip-domain",
    name: "IP & Domain Intelligence",
    description:
      "Network entity evaluation. Inspects IP version, global routability, reverse DNS PTR records, authoritative DNS records (A, MX, NS, TXT), and domain registration metadata (RDAP).",
    icon: Radio,
    method: "POST",
    endpoint: "/api/v1/ip-domain/analyze",
    payloadType: '{ "query": "198.51.100.24" }',
    rateLimit: "Standard bus quota",
    status: "READY",
    href: "/security-tools/ip-domain-analyzer",
  },
  {
    id: "files-upload",
    name: "File Binary Upload & Header Inspector",
    description:
      "Analyzes uploaded binaries and documents for executable risk, magic bytes MIME mismatches, and disguised double extensions (e.g., .pdf.exe). Calculates MD5, SHA-1, and SHA-256 signatures.",
    icon: FileSearch,
    method: "POST",
    endpoint: "/api/v1/files/analyze",
    payloadType: "multipart/form-data (file: binary)",
    rateLimit: "Standard bus quota",
    status: "READY",
  },
  {
    id: "files-hash",
    name: "Privacy-Preserving File Hash Inspector",
    description:
      "Verifies cryptographic signatures against threat databases without transmitting the underlying file content across the network. Supports MD5 (32 hex), SHA-1 (40 hex), and SHA-256 (64 hex).",
    icon: FileSearch,
    method: "POST",
    endpoint: "/api/v1/files/check-hash",
    payloadType: '{ "hash_value": "sha256...", "filename": "sample.exe" }',
    rateLimit: "Standard bus quota",
    status: "READY",
  },
  {
    id: "password",
    name: "Password Breach Verifier (k-Anonymity)",
    description:
      "Zero-knowledge password breach lookup using HIBP k-anonymity. Sends only the first 5 characters of the SHA-1 hash; raw passwords never leave the browser. Handles upstream 503 unavailability without false-clean verdicts.",
    icon: Lock,
    method: "GET",
    endpoint: "/api/v1/password/breached/{hash_prefix}",
    payloadType: "5-character hexadecimal SHA-1 prefix (^[0-9A-Fa-f]{5}$)",
    rateLimit: "HIBP API compliant",
    status: "READY",
  },
];

export default function SecurityToolsPage() {
  return (
    <PageContainer>
      <PageHeader
        editorialTag="VERIFIED DEFENSE SUITE // CORE MODULES"
        title="Security Tools"
        description="Standardized verification modules backed directly by the Python FastAPI engine. Decoupled, type-safe execution architecture."
        badge={
          <Badge variant="monolithic" radius="xs">
            6 MODULES ACTIVE
          </Badge>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {toolModules.map((tool) => {
          const Icon = tool.icon;
          return (
            <div
              key={tool.id}
              className="p-5 glass-panel border border-cyber-border rounded-xs space-y-4 hover:border-cyber-accent/50 transition-all flex flex-col justify-between relative group"
            >
              {/* Corner Monolithic Framing */}
              <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
              <span className="pointer-events-none absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
              <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
              <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />

              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="flex h-8 w-8 items-center justify-center border border-cyber-accent/40 bg-cyber-accent-subtle rounded-xs">
                      <Icon className="h-4 w-4 text-cyber-accent" />
                    </div>
                    <span className="font-mono text-sm font-semibold text-cyber-text-primary">
                      {tool.name}
                    </span>
                  </div>
                  <Badge variant="arctic" radius="xs">
                    {tool.status}
                  </Badge>
                </div>

                <p className="text-xs text-cyber-text-secondary leading-relaxed font-sans">
                  {tool.description}
                </p>

                {/* Technical Endpoint Specs */}
                <div className="p-2.5 bg-cyber-bg border border-cyber-border/70 rounded-xs space-y-1.5 text-[11px] font-mono">
                  <div className="flex items-center justify-between text-cyber-text-dim">
                    <span>METHOD / ENDPOINT:</span>
                    <span className="text-cyber-text-primary">
                      <span className="text-cyber-accent">{tool.method}</span> {tool.endpoint}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-cyber-text-dim">
                    <span>SCHEMA EXPECTED:</span>
                    <span className="text-cyber-text-secondary truncate max-w-[220px]">
                      {tool.payloadType}
                    </span>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-cyber-border/40 flex items-center justify-between text-[11px] font-mono text-cyber-text-dim">
                <span>QUOTA: {tool.rateLimit}</span>
                {tool.href ? (
                  <Link
                    href={tool.href}
                    className="text-cyber-accent hover:underline flex items-center gap-1 text-[10px] uppercase font-semibold"
                  >
                    <span>{tool.id === "scanner" ? "LAUNCH SCANNER" : "LAUNCH ANALYZER"}</span>
                    <ArrowRight className="h-3 w-3" />
                  </Link>
                ) : (
                  <span className="text-cyber-accent uppercase text-[10px]">
                    FASTAPI CONNECTED
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Resilient Password Breach Verifier (k-Anonymity) */}
      <PasswordChecker />
    </PageContainer>
  );
}

