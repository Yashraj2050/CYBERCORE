"use client";

import * as React from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  Database,
  ExternalLink,
  Copy,
  Check,
  Zap,
  Activity,
  Layers,
  Lock,
  Unlock,
  AlertOctagon,
  ArrowUpRight,
  Info,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { UrlScanResult } from "@/types/scanner";

interface ScanAssessmentHeaderProps {
  scan: UrlScanResult;
}

export function ScanAssessmentHeader({ scan }: ScanAssessmentHeaderProps) {
  const [copiedId, setCopiedId] = React.useState(false);
  const [copiedUrl, setCopiedUrl] = React.useState(false);

  const copyScanId = () => {
    navigator.clipboard.writeText(scan.scan_id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const copyTargetUrl = () => {
    navigator.clipboard.writeText(scan.url);
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  // Determine risk category styles and labels directly from backend contract
  const numericScore = typeof scan.risk_score === "number" ? scan.risk_score : null;
  const isScoreAvailable = numericScore !== null;
  const isConfidenceUnavailable = scan.confidence === "UNAVAILABLE";
  const rawCategory = (scan.risk_category || "UNKNOWN").toUpperCase();
  const isUnassessed = isConfidenceUnavailable || !isScoreAvailable || rawCategory === "INSUFFICIENT_EVIDENCE" || rawCategory === "UNVERIFIED";
  const riskCategory = isUnassessed ? (rawCategory === "INSUFFICIENT_EVIDENCE" ? "INSUFFICIENT_EVIDENCE" : "UNASSESSED") : rawCategory;

  const isDangerousTarget =
    riskCategory === "CRITICAL" ||
    riskCategory === "MALICIOUS" ||
    riskCategory === "HIGH_RISK" ||
    riskCategory === "HIGH" ||
    scan.is_malware === true ||
    scan.is_phishing === true ||
    scan.malware_status === "SUSPECTED_MALWARE" ||
    scan.phishing_status === "SUSPECTED_PHISHING";

  const getProgressBarColor = () => {
    if (numericScore === null) return "bg-cyber-text-dim";
    if (numericScore >= 75) return "bg-cyber-threat-critical";
    if (numericScore >= 50) return "bg-cyber-threat-high";
    if (numericScore >= 25) return "bg-cyber-threat-medium";
    return "bg-cyber-threat-secure";
  };

  const progressBarWidth =
    numericScore !== null ? `${Math.min(100, Math.max(5, numericScore))}%` : "0%";

  const getRiskVariant = (category: string) => {
    switch (category) {
      case "MALICIOUS":
      case "CRITICAL":
        return "critical";
      case "HIGH_RISK":
      case "HIGH":
        return "high";
      case "SUSPICIOUS":
      case "MODERATE":
        return "medium";
      case "LOW_RISK":
      case "MODERATE_LOW":
      case "LOW":
        return "low";
      case "NO_KNOWN_THREATS":
      case "CLEAN":
        return "secure";
      case "INSUFFICIENT_EVIDENCE":
      case "UNVERIFIED":
      case "UNASSESSED":
      default:
        return "outline";
    }
  };

  const getConfidenceVariant = (conf: string) => {
    switch (conf.toUpperCase()) {
      case "HIGH":
        return "arctic";
      case "MEDIUM":
        return "medium";
      case "LOW":
        return "monolithic";
      case "UNAVAILABLE":
      default:
        return "outline";
    }
  };

  const formattedDate = React.useMemo(() => {
    try {
      const d = new Date(scan.scanned_at);
      return isNaN(d.getTime()) ? scan.scanned_at : d.toLocaleString("en-US", {
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZoneName: "short",
      });
    } catch {
      return scan.scanned_at;
    }
  }, [scan.scanned_at]);

  return (
    <div className="glass-panel p-5 lg:p-6 space-y-6 relative rounded-xs group border border-cyber-border">
      {/* Corner Monolithic Framing */}
      <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

      {/* Top Meta Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyber-border pb-4 text-xs font-mono">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-cyber-text-dim uppercase text-[10px] tracking-wider">SCAN ID:</span>
          <code className="text-cyber-text-secondary bg-cyber-bg-secondary px-2 py-0.5 border border-cyber-border">
            {scan.scan_id}
          </code>
          <button
            type="button"
            onClick={copyScanId}
            className="text-cyber-text-muted hover:text-cyber-text-primary transition-colors p-1"
            title="Copy Scan ID"
          >
            {copiedId ? <Check className="h-3 w-3 text-cyber-threat-secure" /> : <Copy className="h-3 w-3" />}
          </button>

          {scan.from_cache ? (
            <Badge variant="outline" className="text-[10px] text-cyber-text-muted">
              <Database className="h-2.5 w-2.5 mr-1" /> CACHE HIT
            </Badge>
          ) : (
            <Badge variant="arctic" className="text-[10px]">
              <Zap className="h-2.5 w-2.5 mr-1" /> LIVE ENGINE
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-4 text-cyber-text-dim text-[11px]">
          <span className="flex items-center gap-1.5">
            <Clock className="h-3 w-3 text-cyber-accent/60" />
            <span className="text-cyber-text-muted">{formattedDate}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <Activity className="h-3 w-3 text-cyber-accent/60" />
            <span className="text-cyber-text-muted">{scan.scan_duration_ms} ms</span>
          </span>
        </div>
      </div>

      {/* Main Grid: Target Details & Monolithic Score Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Target URL, Domain, Indicators */}
        <div className="lg:col-span-8 space-y-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">
              <span>TARGET INVESTIGATION OBJECT</span>
              <span className="text-cyber-border-strong">{"//"}</span>
              {scan.domain ? (
                <Link
                  href={`/security-tools/ip-domain-analyzer?query=${encodeURIComponent(scan.domain)}`}
                  className="text-cyber-accent hover:underline hover:text-cyber-accent/80 transition-colors inline-flex items-center gap-1 font-mono"
                  title={`Investigate domain ${scan.domain} in IP & Domain Intelligence Analyzer`}
                >
                  <span>{scan.domain}</span>
                  <ArrowUpRight className="h-2.5 w-2.5 opacity-70" />
                </Link>
              ) : (
                <span className="text-cyber-accent">UNKNOWN</span>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2 break-all">
              {isDangerousTarget ? (
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-base sm:text-lg md:text-xl font-mono font-medium text-cyber-threat-critical bg-cyber-threat-critical-bg/50 px-2.5 py-1 border border-cyber-threat-critical-border">
                    {scan.url}
                  </span>
                  <Badge variant="critical" className="text-[10px] uppercase tracking-wider py-0.5">
                    DIRECT NAVIGATION DISABLED (UNSAFE TARGET)
                  </Badge>
                </div>
              ) : (
                <a
                  href={scan.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-base sm:text-lg md:text-xl font-mono font-medium text-cyber-text-primary hover:text-cyber-accent transition-colors flex items-center gap-2 group"
                >
                  <span>{scan.url}</span>
                  <ExternalLink className="h-3.5 w-3.5 text-cyber-text-muted opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                </a>
              )}
              <button
                type="button"
                onClick={copyTargetUrl}
                className="text-cyber-text-muted hover:text-cyber-text-primary transition-colors p-1.5 border border-cyber-border bg-cyber-bg-secondary hover:bg-cyber-bg-surface flex items-center gap-1 text-[11px] font-mono shrink-0"
                title="Copy Target URL to clipboard"
              >
                {copiedUrl ? (
                  <>
                    <Check className="h-3 w-3 text-cyber-threat-secure" />
                    <span className="text-cyber-threat-secure">COPIED</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" />
                    <span>COPY URL</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Key Boolean Indicators Pill Strip */}
          <div className="flex flex-wrap items-center gap-2 pt-2">
            {/* Phishing Flag */}
            {scan.phishing_status === "CONFIRMED_PHISHING" || scan.is_phishing === true ? (
              <Badge variant="critical" className="gap-1 px-2.5 py-1">
                <AlertOctagon className="h-3 w-3" /> PHISHING CONFIRMED
              </Badge>
            ) : scan.phishing_status === "SUSPECTED_PHISHING" ? (
              <Badge variant="high" className="gap-1 px-2.5 py-1">
                <AlertTriangle className="h-3 w-3" /> SUSPECTED PHISHING
              </Badge>
            ) : scan.phishing_status === "NO_KNOWN_DETECTION" || scan.is_phishing === false ? (
              <Badge variant="secure" className="gap-1 px-2.5 py-1">
                <ShieldCheck className="h-3 w-3" /> NO PHISHING PATTERNS
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1 px-2.5 py-1">
                <ShieldAlert className="h-3 w-3" /> PHISHING CHECK UNVERIFIED
              </Badge>
            )}

            {/* Malware Flag */}
            {scan.malware_status === "CONFIRMED_MALWARE" || scan.is_malware === true ? (
              <Badge variant="critical" className="gap-1 px-2.5 py-1">
                <AlertTriangle className="h-3 w-3" /> MALWARE CONFIRMED
              </Badge>
            ) : scan.malware_status === "SUSPECTED_MALWARE" ? (
              <Badge variant="high" className="gap-1 px-2.5 py-1">
                <AlertTriangle className="h-3 w-3" /> SUSPECTED PAYLOAD / MALWARE
              </Badge>
            ) : scan.malware_status === "NO_KNOWN_DETECTION" || scan.is_malware === false ? (
              <Badge variant="secure" className="gap-1 px-2.5 py-1">
                <ShieldCheck className="h-3 w-3" /> NO MALWARE SIGNATURES
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1 px-2.5 py-1">
                <ShieldAlert className="h-3 w-3" /> MALWARE CHECK UNVERIFIED
              </Badge>
            )}

            {/* SSL Status */}
            {scan.ssl_valid === true ? (
              <Badge variant="secure" className="gap-1 px-2.5 py-1">
                <Lock className="h-3 w-3" /> SSL CERTIFICATE VALID
              </Badge>
            ) : scan.ssl_valid === false ? (
              <Badge variant="high" className="gap-1 px-2.5 py-1">
                <Unlock className="h-3 w-3" /> INVALID / EXPIRED SSL
              </Badge>
            ) : (
              <Badge variant="outline" className="gap-1 px-2.5 py-1">
                <ShieldAlert className="h-3 w-3" /> SSL UNVERIFIED
              </Badge>
            )}
          </div>

          {/* Engine Confidence & Coverage Telemetry */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 pt-3 border-t border-cyber-border font-mono text-xs">
            <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">ASSESSMENT CONFIDENCE</div>
              <div className="flex items-center gap-1.5">
                <Badge variant={getConfidenceVariant(scan.confidence)} className="text-[10px]">
                  {scan.confidence || "MEDIUM"}
                </Badge>
              </div>
            </div>

            <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">ENGINE COVERAGE</div>
              <div className="text-sm font-semibold text-cyber-text-primary flex items-baseline gap-1">
                <span>{scan.coverage_percent || 0}%</span>
                <span className="text-[10px] text-cyber-text-dim font-normal">subsystems active</span>
              </div>
            </div>

            <div className="col-span-2 sm:col-span-1 p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">UNAVAILABLE CHECKS</div>
              <div className="text-sm font-semibold text-cyber-text-secondary">
                {scan.unavailable_checks && scan.unavailable_checks.length > 0 ? (
                  <span className="text-cyber-threat-medium text-xs">
                    {scan.unavailable_checks.length} checks offline
                  </span>
                ) : (
                  <span className="text-cyber-threat-secure text-xs">ALL ONLINE</span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Monolithic Brutalist Composite Risk Score */}
        <div className="lg:col-span-4 flex flex-col justify-between p-5 bg-cyber-bg-secondary border border-cyber-border-strong relative overflow-hidden">
          {/* Subtle architectural grid pattern */}
          <div className="absolute top-0 right-0 p-3 opacity-10 pointer-events-none">
            <Layers className="h-24 w-24 text-cyber-accent" />
          </div>

          <div className="space-y-1 relative z-10">
            <div className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim flex items-center justify-between">
              <span>COMPOSITE RISK INDEX</span>
              <span>SCALE: 0–100</span>
            </div>
            <div className="flex items-baseline gap-3 pt-2">
              <span className="text-5xl lg:text-6xl font-mono font-bold tracking-tighter text-cyber-text-primary">
                {isScoreAvailable ? numericScore : "--"}
              </span>
              <span className="text-xs font-mono text-cyber-text-dim">/ 100</span>
            </div>
          </div>

          {/* Status Classification Badge */}
          <div className="pt-6 relative z-10 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">VERDICT</span>
              <Badge variant={getRiskVariant(riskCategory)} className="text-xs px-2.5 py-1">
                {riskCategory === "INSUFFICIENT_EVIDENCE"
                  ? "INSUFFICIENT EVIDENCE"
                  : riskCategory === "HIGH_RISK"
                  ? "HIGH RISK TARGET"
                  : riskCategory === "LOW_RISK"
                  ? "LOW RISK TARGET"
                  : riskCategory === "UNASSESSED" || riskCategory === "UNVERIFIED"
                  ? "UNASSESSED TARGET"
                  : `${riskCategory.replace(/_/g, "-")} THREAT`}
              </Badge>
            </div>

            {/* Linear Progress Bar for Risk */}
            <div className="w-full bg-cyber-bg-tertiary h-1.5 overflow-hidden border border-cyber-border">
              <div
                className={`h-full transition-all duration-500 ${getProgressBarColor()}`}
                style={{ width: progressBarWidth }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Explicit Security & Coverage Notice */}
      <div className="p-3.5 bg-cyber-bg-secondary border border-cyber-border text-[11px] font-mono text-cyber-text-secondary flex items-start gap-2.5">
        <Info className="h-4 w-4 text-cyber-accent shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-cyber-text-primary uppercase text-[10px] tracking-wider">
              EVALUATION BOUNDARY & SECURITY NOTICE
            </span>
            <Badge variant="monolithic" className="text-[9px]">
              {scan.coverage_percent || 0}% SUBSYSTEM COVERAGE
            </Badge>
          </div>
          <p className="text-cyber-text-muted leading-relaxed text-[11px]">
            Composite risk index is calculated strictly from {scan.coverage_percent || 0}% active verification subsystems
            {scan.unavailable_checks && scan.unavailable_checks.length > 0 ? (
              <> ({scan.unavailable_checks.length} unavailable check{scan.unavailable_checks.length > 1 ? "s" : ""}: <span className="text-cyber-threat-medium font-semibold">{scan.unavailable_checks.join(", ")}</span>)</>
            ) : " (all checks online)"}.
            An evaluation score of zero or absence of heuristic detections does <strong className="text-cyber-text-primary font-semibold">not</strong> guarantee that the destination is harmless. Never treat unavailable detection engines as proof of safety.
          </p>
        </div>
      </div>
    </div>
  );
}
