"use client";

import * as React from "react";
import {
  Globe,
  Radio,
  Server,
  Layers,
  Terminal,
  Clock,
  Fingerprint,
  Info,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { IpDomainRawViewer } from "./ip-domain-raw-viewer";
import type { IpAnalysisResponse } from "@/types/ip-domain";

interface IpInvestigationViewProps {
  result: IpAnalysisResponse;
}

export function IpInvestigationView({ result }: IpInvestigationViewProps) {
  const isV4 = result.ip_version === 4;
  const hasPtr = Boolean(result.reverse_dns && result.reverse_dns.length > 0);
  const riskScore = result.reputation?.risk_score ?? 0;
  const verdict = result.reputation?.verdict ?? "UNKNOWN";

  const getVerdictVariant = (v: string) => {
    switch (v) {
      case "BENIGN":
        return "secure";
      case "UNKNOWN_HOST":
        return "medium";
      case "SUSPICIOUS":
        return "high";
      case "MALICIOUS":
        return "critical";
      default:
        return "outline";
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Target Identity Header */}
      <div className="glass-panel p-5 lg:p-6 space-y-6 relative rounded-xs group border border-cyber-border">
        {/* Corner Monolithic Framing */}
        <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

        {/* Top Meta Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-cyber-text-dim uppercase text-[10px] tracking-wider flex items-center gap-1.5">
              <Radio className="h-3.5 w-3.5 text-cyber-accent" />
              INVESTIGATED NETWORK ENTITY:
            </span>
            <code className="text-cyber-text-primary bg-cyber-bg-secondary px-2 py-0.5 border border-cyber-border text-sm font-bold">
              {result.target}
            </code>
          </div>

          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-[10px] font-mono">
              {isV4 ? "IPv4 PROTOCOL" : "IPv6 PROTOCOL"}
            </Badge>
            <Badge variant={result.is_global ? "secure" : "outline"} className="text-[10px] font-mono">
              {result.is_global ? "GLOBALLY ROUTABLE" : "NON-GLOBAL"}
            </Badge>
            {result.scanned_at && (
              <span className="text-[10px] font-mono text-cyber-text-dim flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {new Date(result.scanned_at).toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        {/* Main Header Strip */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-8 space-y-4">
            <div className="space-y-1">
              <div className="text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">
                NETWORK ADDRESS CLASSIFICATION
              </div>
              <h2 className="text-2xl sm:text-3xl font-mono font-bold tracking-tight text-cyber-text-primary">
                {result.target}
              </h2>
              <p className="text-xs font-mono text-cyber-text-secondary">
                Publicly accessible internet host with verified {isV4 ? "IPv4 32-bit" : "IPv6 128-bit"} network architecture.
              </p>
            </div>

            {/* Quick Technical Badges */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 font-mono text-xs pt-2">
              <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                  ADDRESS FAMILY
                </div>
                <div className="text-sm font-semibold text-cyber-text-primary">
                  IPv{result.ip_version}
                </div>
              </div>

              <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                  GLOBAL ROUTABILITY
                </div>
                <div className="text-sm font-semibold text-cyber-threat-secure flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>PUBLIC</span>
                </div>
              </div>

              <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1 col-span-2 sm:col-span-1">
                <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                  REVERSE DNS
                </div>
                <div className={`text-xs font-semibold truncate ${hasPtr ? "text-cyber-text-primary" : "text-cyber-text-dim"}`} title={result.reverse_dns || "Unconfigured"}>
                  {result.reverse_dns || "NOT CONFIGURED"}
                </div>
              </div>
            </div>
          </div>

          {/* Right Column: Brutalist Heuristic Score Card */}
          <div className="lg:col-span-4 flex flex-col justify-between p-5 bg-cyber-bg-secondary border border-cyber-border-strong relative overflow-hidden">
            <div className="absolute top-0 right-0 p-3 opacity-10 pointer-events-none">
              <Layers className="h-24 w-24 text-cyber-accent" />
            </div>

            <div className="space-y-1 relative z-10">
              <div className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim flex items-center justify-between">
                <span>HEURISTIC ASSESSMENT</span>
                <span>0–100 SCALE</span>
              </div>
              <div className="flex items-baseline gap-3 pt-2">
                <span className="text-5xl font-mono font-bold tracking-tighter text-cyber-text-primary">
                  {riskScore}
                </span>
                <span className="text-xs font-mono text-cyber-text-dim">/ 100</span>
              </div>
            </div>

            <div className="pt-6 relative z-10 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">
                  VERDICT CLASSIFICATION
                </span>
                <Badge variant={getVerdictVariant(verdict)} className="text-xs px-2.5 py-0.5">
                  {verdict.replace(/_/g, " ")}
                </Badge>
              </div>

              <p className="text-[10px] font-mono text-cyber-text-dim leading-tight pt-1">
                Score derived from reverse PTR existence and network routability. Does not represent external blacklist reputation.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Technical Topology Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Network & Routing Classification */}
        <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
            <Server className="h-4 w-4 text-cyber-accent" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              NETWORK ROUTING ATTRIBUTES
            </h3>
          </div>

          <div className="divide-y divide-cyber-border font-mono text-xs">
            <div className="py-2.5 flex items-center justify-between">
              <span className="text-cyber-text-dim">IP Protocol Standard</span>
              <span className="text-cyber-text-primary font-semibold">IPv{result.ip_version} Unicast</span>
            </div>

            <div className="py-2.5 flex items-center justify-between">
              <span className="text-cyber-text-dim">Routable Scope</span>
              <span className="text-cyber-threat-secure font-semibold">
                {result.is_global ? "Global Public Internet" : "Non-Global / Local"}
              </span>
            </div>

            <div className="py-2.5 flex items-center justify-between">
              <span className="text-cyber-text-dim">Reverse PTR Hostname</span>
              <span className="text-cyber-text-primary font-semibold truncate max-w-[200px]" title={result.reverse_dns || ""}>
                {result.reverse_dns || "No PTR Record"}
              </span>
            </div>

            <div className="py-2.5 flex items-center justify-between">
              <span className="text-cyber-text-dim">Reverse Lookup Status</span>
              <span className={hasPtr ? "text-cyber-threat-secure" : "text-cyber-threat-medium"}>
                {hasPtr ? "PTR Confirmed" : "PTR Missing"}
              </span>
            </div>
          </div>

          {/* Missing / Limitation Callout */}
          <div className="p-3 bg-cyber-bg-secondary border border-cyber-border flex items-start gap-2 text-[11px] font-mono text-cyber-text-dim">
            <Info className="h-3.5 w-3.5 text-cyber-accent shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              Autonomous System Numbers (ASN), ISP identification, and Geolocation metadata are not supported by the
              current local heuristic engine.
            </p>
          </div>
        </div>

        {/* DNS Reverse Resolution (PTR) */}
        <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-cyber-border pb-3">
            <Globe className="h-4 w-4 text-cyber-accent" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              DNS REVERSE RESOLUTION (PTR)
            </h3>
          </div>

          <div className="space-y-3 font-mono">
            <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                PTR RECORD VALUE
              </div>
              <div className="text-xs text-cyber-text-primary font-semibold break-all">
                {result.dns?.ptr || "No PTR record found"}
              </div>
            </div>

            <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-2 text-xs">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                HEURISTIC REASONING NOTES
              </div>
              <ul className="space-y-1 text-cyber-text-secondary text-[11px]">
                {result.reputation?.notes && result.reputation.notes.length > 0 ? (
                  result.reputation.notes.map((note, idx) => (
                    <li key={idx} className="flex items-center gap-1.5">
                      <span className="h-1 w-1 bg-cyber-accent rounded-full" />
                      <span>{note}</span>
                    </li>
                  ))
                ) : (
                  <li className="text-cyber-text-dim italic">No additional heuristic notes returned.</li>
                )}
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* 3. Raw Technical Response Viewer */}
      <IpDomainRawViewer data={result} target={result.target} />
    </div>
  );
}

