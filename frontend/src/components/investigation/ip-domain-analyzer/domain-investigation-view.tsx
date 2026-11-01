"use client";

import * as React from "react";
import {
  Globe,
  Radio,
  Server,
  Layers,
  Terminal,
  Clock,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  Calendar,
  Building,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Mail,
  FileText,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { IpDomainRawViewer } from "./ip-domain-raw-viewer";
import type { DomainAnalysisResponse, DmarcStatus } from "@/types/ip-domain";

interface DomainInvestigationViewProps {
  result: DomainAnalysisResponse;
}

export function DomainInvestigationView({ result }: DomainInvestigationViewProps) {
  const dns = result.dns || {
    a_records: [],
    mx_records: [],
    ns_records: [],
    txt_records: [],
    has_spf: false,
    has_dmarc: null,
    has_dkim_hint: false,
    dmarc_record: null,
    dmarc_status: null,
  };

  const reg = result.registration || {};
  const hasRegError = Boolean(reg.error);
  const rep = result.reputation || { score: 0, confidence: "MEDIUM", findings: [] };

  const getDmarcBadge = (status: DmarcStatus | null, hasDmarc: boolean | null) => {
    switch (status) {
      case "VALID":
        return <Badge variant="secure" className="text-[10px]">VALID DMARC (RFC 7489)</Badge>;
      case "MISSING":
        return <Badge variant="high" className="text-[10px]">POLICY MISSING</Badge>;
      case "MALFORMED":
        return <Badge variant="critical" className="text-[10px]">RECORD MALFORMED</Badge>;
      case "UNAVAILABLE":
        return <Badge variant="outline" className="text-[10px] text-cyber-text-dim">DNS UNAVAILABLE</Badge>;
      default:
        if (hasDmarc === true) return <Badge variant="secure" className="text-[10px]">POLICY ACTIVE</Badge>;
        if (hasDmarc === false) return <Badge variant="high" className="text-[10px]">POLICY MISSING</Badge>;
        return <Badge variant="outline" className="text-[10px]">UNVERIFIED</Badge>;
    }
  };

  const getConfidenceVariant = (conf: string) => {
    switch (conf.toUpperCase()) {
      case "HIGH":
        return "secure";
      case "MEDIUM":
        return "medium";
      case "LOW":
        return "high";
      default:
        return "outline";
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Domain Identity Header */}
      <div className="glass-panel p-5 lg:p-6 space-y-6 relative rounded-xs group border border-cyber-border">
        {/* Corner Monolithic Framing */}
        <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4 text-xs font-mono">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-cyber-text-dim uppercase text-[10px] tracking-wider flex items-center gap-1.5">
              <Globe className="h-3.5 w-3.5 text-cyber-accent" />
              INVESTIGATED DOMAIN ENTITY:
            </span>
            <code className="text-cyber-text-primary bg-cyber-bg-secondary px-2 py-0.5 border border-cyber-border text-sm font-bold">
              {result.target}
            </code>
          </div>

          <div className="flex items-center gap-2">
            <Badge variant="arctic" className="text-[10px] font-mono">
              DNS & RDAP TOPOLOGY
            </Badge>
            {result.scanned_at && (
              <span className="text-[10px] font-mono text-cyber-text-dim flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {new Date(result.scanned_at).toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        {/* Main Grid: Classification & Score Card */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-8 space-y-4">
            <div className="space-y-1">
              <div className="text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">
                DOMAIN ARCHITECTURE & RESOLUTION
              </div>
              <h2 className="text-2xl sm:text-3xl font-mono font-bold tracking-tight text-cyber-text-primary break-all">
                {result.target}
              </h2>
              <p className="text-xs font-mono text-cyber-text-secondary">
                Technical records resolved via authoritative DNS topology and global RDAP registry.
              </p>
            </div>

            {/* Quick Metrics Strip */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs pt-2">
              <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                  A RECORDS
                </div>
                <div className="text-sm font-semibold text-cyber-text-primary">
                  {dns.a_records ? dns.a_records.length : 0}
                </div>
              </div>

              <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                  MX SERVERS
                </div>
                <div className="text-sm font-semibold text-cyber-text-primary">
                  {dns.mx_records ? dns.mx_records.length : 0}
                </div>
              </div>

              <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                  SPF AUTH
                </div>
                <div className={`text-xs font-semibold ${dns.has_spf ? "text-cyber-threat-secure" : "text-cyber-threat-medium"}`}>
                  {dns.has_spf ? "CONFIGURED" : "NOT DETECTED"}
                </div>
              </div>

              <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                  DMARC STATUS
                </div>
                <div className="text-xs font-semibold truncate">
                  {dns.dmarc_status || (dns.has_dmarc ? "VALID" : "MISSING")}
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
                <span>SCALE: 0–95</span>
              </div>
              <div className="flex items-baseline gap-3 pt-2">
                <span className="text-5xl font-mono font-bold tracking-tighter text-cyber-text-primary">
                  {Math.round(rep.score)}
                </span>
                <span className="text-xs font-mono text-cyber-text-dim">/ 100</span>
              </div>
            </div>

            <div className="pt-6 relative z-10 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">
                  CONFIDENCE TIER
                </span>
                <Badge variant={getConfidenceVariant(rep.confidence)} className="text-xs px-2.5 py-0.5">
                  {rep.confidence} CONFIDENCE
                </Badge>
              </div>

              <p className="text-[10px] font-mono text-cyber-text-dim leading-tight pt-1">
                Derived from domain age, resolution integrity, and nameserver reputation. Does not represent malware telemetry.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Email Authentication Protocol Audit */}
      <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-cyber-accent" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              EMAIL AUTHENTICATION & SPOOFING DEFENSE
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            RFC 7208 (SPF) // RFC 7489 (DMARC)
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono">
          {/* SPF Card */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-cyber-text-primary">Sender Policy (SPF)</span>
              <Badge variant={dns.has_spf ? "secure" : "high"} className="text-[10px]">
                {dns.has_spf ? "SPF ACTIVE" : "SPF ABSENT"}
              </Badge>
            </div>
            <p className="text-[11px] text-cyber-text-dim leading-relaxed">
              {dns.has_spf
                ? "Apex TXT contains valid 'v=spf1' authorization directive specifying allowed sending hosts."
                : "No 'v=spf1' record identified in apex TXT. Domain may be vulnerable to unauthorized sender spoofing."}
            </p>
          </div>

          {/* DMARC Card */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-cyber-text-primary">DMARC Policy</span>
              {getDmarcBadge(dns.dmarc_status, dns.has_dmarc)}
            </div>
            <p className="text-[11px] text-cyber-text-dim leading-relaxed">
              {dns.dmarc_status === "VALID"
                ? "RFC 7489 policy published at _dmarc label. Recipient mail servers can enforce domain alignment."
                : dns.dmarc_status === "UNAVAILABLE"
                ? "DNS resolution for _dmarc timed out or failed. State is unknown and NOT confirmed missing."
                : dns.dmarc_status === "MALFORMED"
                ? "Record discovered at _dmarc label but does not conform to 'v=DMARC1' format requirements."
                : "No DMARC policy discovered at _dmarc label or parent organizational domain."}
            </p>
            {dns.dmarc_record && (
              <div className="text-[10px] bg-cyber-bg p-2 border border-cyber-border text-cyber-text-secondary break-all">
                <code>{dns.dmarc_record}</code>
              </div>
            )}
          </div>

          {/* DKIM Hint Card */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-cyber-text-primary">DKIM Hint</span>
              <Badge variant={dns.has_dkim_hint ? "secure" : "outline"} className="text-[10px]">
                {dns.has_dkim_hint ? "DKIM HINT" : "NO APEX HINT"}
              </Badge>
            </div>
            <p className="text-[11px] text-cyber-text-dim leading-relaxed">
              {dns.has_dkim_hint
                ? "Apex TXT contains 'v=dkim1' pattern hint."
                : "No DKIM hints found in apex TXT records."}
            </p>
            <div className="text-[10px] text-cyber-text-muted italic pt-1 border-t border-cyber-border/60">
              Note: Cryptographic DKIM verification requires selector knowledge (_domainkey). Apex hints do not prove signing.
            </div>
          </div>
        </div>
      </div>

      {/* 3. DNS Technical Topology (A, MX, NS, TXT) */}
      <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-cyber-accent" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              TECHNICAL DNS TOPOLOGY
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            AUTHORITATIVE RESOLVER RESPONSES
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          {/* A Records */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="flex items-center justify-between text-cyber-text-dim text-[10px] uppercase tracking-wider">
              <span>A Records (IPv4 Host Mapping)</span>
              <span>{dns.a_records ? dns.a_records.length : 0} RECORD(S)</span>
            </div>
            {dns.a_records && dns.a_records.length > 0 ? (
              <ul className="space-y-1 text-cyber-text-primary">
                {dns.a_records.map((ip, idx) => (
                  <li key={idx} className="flex items-center gap-2 font-mono">
                    <span className="h-1.5 w-1.5 bg-cyber-accent rounded-none" />
                    <span>{ip}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-cyber-threat-high italic text-[11px]">
                Domain does not resolve to any IPv4 addresses (NXDOMAIN or No A records).
              </div>
            )}
          </div>

          {/* MX Records */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="flex items-center justify-between text-cyber-text-dim text-[10px] uppercase tracking-wider">
              <span>MX Records (Mail Exchangers)</span>
              <span>{dns.mx_records ? dns.mx_records.length : 0} RECORD(S)</span>
            </div>
            {dns.mx_records && dns.mx_records.length > 0 ? (
              <ul className="space-y-1 text-cyber-text-primary">
                {dns.mx_records.map((mx, idx) => (
                  <li key={idx} className="flex items-center gap-2 font-mono break-all">
                    <span className="h-1.5 w-1.5 bg-cyber-threat-secure rounded-none" />
                    <span>{mx}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-cyber-text-dim italic text-[11px]">
                No MX records configured. Domain does not directly accept email.
              </div>
            )}
          </div>

          {/* NS Records */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="flex items-center justify-between text-cyber-text-dim text-[10px] uppercase tracking-wider">
              <span>NS Records (Authoritative Nameservers)</span>
              <span>{dns.ns_records ? dns.ns_records.length : 0} RECORD(S)</span>
            </div>
            {dns.ns_records && dns.ns_records.length > 0 ? (
              <ul className="space-y-1 text-cyber-text-primary">
                {dns.ns_records.map((ns, idx) => (
                  <li key={idx} className="flex items-center gap-2 font-mono break-all">
                    <span className="h-1.5 w-1.5 bg-cyber-accent rounded-none" />
                    <span>{ns}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-cyber-text-dim italic text-[11px]">
                No authoritative nameservers returned.
              </div>
            )}
          </div>

          {/* TXT Records */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="flex items-center justify-between text-cyber-text-dim text-[10px] uppercase tracking-wider">
              <span>TXT Records (Policy & Verification)</span>
              <span>{dns.txt_records ? dns.txt_records.length : 0} RECORD(S)</span>
            </div>
            {dns.txt_records && dns.txt_records.length > 0 ? (
              <ul className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {dns.txt_records.map((txt, idx) => (
                  <li key={idx} className="p-1.5 bg-cyber-bg border border-cyber-border text-cyber-text-secondary text-[11px] font-mono break-all select-all">
                    {txt}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-cyber-text-dim italic text-[11px]">
                No TXT records published at domain apex.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 4. Domain Registration (RDAP) */}
      <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center gap-2">
            <Building className="h-4 w-4 text-cyber-accent" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              REGISTRATION & RDAP METADATA
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            STRUCTURED REGISTRY TELEMETRY
          </span>
        </div>

        {hasRegError ? (
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border font-mono text-xs space-y-1.5">
            <div className="flex items-center gap-2 text-cyber-threat-high font-semibold text-[11px] uppercase">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span>RDAP METADATA LOOKUP NOTICE</span>
            </div>
            <p className="text-cyber-text-secondary text-[11px]">
              Registration telemetry was not returned by the upstream RDAP bootstrap provider:{" "}
              <code className="text-cyber-accent">{reg.error}</code>
            </p>
            <p className="text-[10px] text-cyber-text-dim">
              This occurs for non-existent domains (NXDOMAIN), novel country-code TLDs without open RDAP endpoints, or service timeouts.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-cyber-border font-mono text-xs">
            <div className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="text-cyber-text-dim">Sponsoring Registrar</span>
              <span className="text-cyber-text-primary font-semibold">{reg.registrar || "Not Published"}</span>
            </div>

            <div className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="text-cyber-text-dim">Domain Age</span>
              <span className="text-cyber-text-primary font-semibold">
                {reg.domain_age_days != null ? `${reg.domain_age_days.toLocaleString()} days` : "Unknown"}
              </span>
            </div>

            <div className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="text-cyber-text-dim">Initial Registration Date</span>
              <span className="text-cyber-text-primary font-semibold">{reg.registration_date || "Unknown"}</span>
            </div>

            <div className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="text-cyber-text-dim">Registry Expiration Date</span>
              <span className="text-cyber-text-primary font-semibold">{reg.expiration_date || "Unknown"}</span>
            </div>

            <div className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
              <span className="text-cyber-text-dim">Last Updated Record</span>
              <span className="text-cyber-text-primary font-semibold">{reg.last_updated || "Unknown"}</span>
            </div>

            {reg.status && reg.status.length > 0 && (
              <div className="py-2.5 space-y-1.5">
                <span className="text-cyber-text-dim block">Registry Status Flags</span>
                <div className="flex flex-wrap gap-1.5">
                  {reg.status.map((st, idx) => (
                    <Badge key={idx} variant="outline" className="text-[10px]">
                      {st}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 5. Heuristic Assessment & Evidentiary Findings */}
      <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyber-accent" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              HEURISTIC ASSESSMENT & TECHNICAL EVIDENCE
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            EVALUATION RATIONALE
          </span>
        </div>

        <div className="space-y-3 font-mono text-xs">
          <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-2">
            <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider font-semibold">
              TECHNICAL FINDINGS & EVIDENCE LIST
            </div>
            {rep.findings && rep.findings.length > 0 ? (
              <ul className="space-y-1 text-cyber-text-primary">
                {rep.findings.map((f, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-[11px]">
                    <span className="h-1.5 w-1.5 bg-cyber-accent rounded-none shrink-0 mt-1" />
                    <span className="leading-relaxed">{f}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-cyber-text-dim italic text-[11px]">
                Zero adverse heuristic signals identified in DNS or RDAP topology.
              </div>
            )}
          </div>

          <div className="p-3 bg-cyber-bg border border-cyber-border text-[11px] text-cyber-text-dim leading-relaxed flex items-start gap-2">
            <Info className="h-3.5 w-3.5 text-cyber-accent shrink-0 mt-0.5" />
            <p>
              Note: Domain reputation is scored deterministically based on domain age thresholds, registry status,
              and nameserver keyword indicators. These technical signals do not represent verified threat intelligence
              or proof of maliciousness.
            </p>
          </div>
        </div>
      </div>

      {/* 6. Raw Technical Response Viewer */}
      <IpDomainRawViewer data={result} target={result.target} />
    </div>
  );
}

