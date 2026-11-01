"use client";

import * as React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Fingerprint,
  Copy,
  Check,
  Layers,
  Terminal,
  Activity,
  FileText,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { MessageAnalyzeResult } from "@/types/messages";

interface MessageAnalysisHeaderProps {
  result: MessageAnalyzeResult;
}

export function MessageAnalysisHeader({ result }: MessageAnalysisHeaderProps) {
  const [copiedHash, setCopiedHash] = React.useState(false);

  const copyHash = () => {
    if (!result.message_hash) return;
    navigator.clipboard.writeText(result.message_hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const riskLevel = (result.risk_level || "UNKNOWN").toUpperCase();
  const riskScore = typeof result.risk_score === "number" ? result.risk_score : 0;

  const getRiskVariant = (level: string) => {
    switch (level) {
      case "CRITICAL":
        return "critical";
      case "HIGH_RISK":
      case "HIGH":
        return "high";
      case "SUSPICIOUS":
      case "MEDIUM":
        return "medium";
      case "LOW_RISK":
      case "LOW":
        return "low";
      case "SAFE":
      case "CLEAN":
        return "secure";
      default:
        return "outline";
    }
  };

  const getProgressBarColor = () => {
    if (riskScore >= 80) return "bg-cyber-threat-critical";
    if (riskScore >= 60) return "bg-cyber-threat-high";
    if (riskScore >= 35) return "bg-cyber-threat-medium";
    if (riskScore >= 15) return "bg-cyber-threat-low";
    return "bg-cyber-threat-secure";
  };

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
          <span className="text-cyber-text-dim uppercase text-[10px] tracking-wider flex items-center gap-1.5">
            <Fingerprint className="h-3.5 w-3.5 text-cyber-accent" />
            MESSAGE SHA-256 HASH:
          </span>
          <code className="text-cyber-text-secondary bg-cyber-bg-secondary px-2 py-0.5 border border-cyber-border text-[11px] truncate max-w-xs sm:max-w-md">
            {result.message_hash || "Uncomputed"}
          </code>
          {result.message_hash && (
            <button
              type="button"
              onClick={copyHash}
              className="text-cyber-text-muted hover:text-cyber-text-primary transition-colors p-1"
              title="Copy SHA-256 Digest"
            >
              {copiedHash ? (
                <Check className="h-3 w-3 text-cyber-threat-secure" />
              ) : (
                <Copy className="h-3 w-3" />
              )}
            </button>
          )}
        </div>

        <div className="flex items-center gap-3 text-cyber-text-dim text-[11px]">
          <Badge variant="arctic" className="text-[10px]">
            HEURISTIC ENGINE EVALUATED
          </Badge>
        </div>
      </div>

      {/* Main Grid: Scam Classification & Monolithic Score Card */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Classification, Summary, and Scope */}
        <div className="lg:col-span-8 space-y-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">
              <span>PRIMARY THREAT CLASSIFICATION</span>
              <span className="text-cyber-border-strong">{"//"}</span>
              <span className="text-cyber-accent">PATTERN TAXONOMY</span>
            </div>

            <h2 className="text-xl sm:text-2xl font-mono font-bold tracking-tight text-cyber-text-primary flex items-center gap-3">
              <span>{result.scam_type || "No Specific Scam Signature"}</span>
            </h2>
          </div>

          {/* Official Rule-Based Summary Banner */}
          <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-1.5 font-mono">
            <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider flex items-center gap-1.5">
              <Terminal className="h-3 w-3 text-cyber-accent" />
              <span>HEURISTIC ASSESSMENT SUMMARY</span>
            </div>
            <p className="text-xs sm:text-sm text-cyber-text-primary leading-relaxed">
              {result.summary}
            </p>
          </div>

          {/* Quick Metrics Strip */}
          <div className="grid grid-cols-3 gap-3 font-mono text-xs">
            <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                PATTERNS TRIGGERED
              </div>
              <div className="text-sm font-semibold text-cyber-text-primary">
                {result.indicators ? result.indicators.length : 0}
              </div>
            </div>

            <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                EXTRACTED URLS
              </div>
              <div className="text-sm font-semibold text-cyber-text-primary">
                {result.urls_found ? result.urls_found.length : 0}
              </div>
            </div>

            <div className="p-3 bg-cyber-bg-secondary border border-cyber-border space-y-1">
              <div className="text-[10px] text-cyber-text-dim uppercase tracking-wider">
                TACTICS DETECTED
              </div>
              <div className="text-sm font-semibold text-cyber-text-primary">
                {result.manipulation_tactics ? result.manipulation_tactics.length : 0}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Monolithic Brutalist Composite Risk Score */}
        <div className="lg:col-span-4 flex flex-col justify-between p-5 bg-cyber-bg-secondary border border-cyber-border-strong relative overflow-hidden">
          <div className="absolute top-0 right-0 p-3 opacity-10 pointer-events-none">
            <Layers className="h-24 w-24 text-cyber-accent" />
          </div>

          <div className="space-y-1 relative z-10">
            <div className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim flex items-center justify-between">
              <span>HEURISTIC RISK SCORE</span>
              <span>SCALE: 0–98</span>
            </div>
            <div className="flex items-baseline gap-3 pt-2">
              <span className="text-5xl lg:text-6xl font-mono font-bold tracking-tighter text-cyber-text-primary">
                {riskScore}
              </span>
              <span className="text-xs font-mono text-cyber-text-dim">/ 100</span>
            </div>
          </div>

          {/* Verdict Classification Badge */}
          <div className="pt-6 relative z-10 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase text-cyber-text-dim tracking-wider">
                RISK LEVEL
              </span>
              <Badge variant={getRiskVariant(riskLevel)} className="text-xs px-2.5 py-1">
                {riskLevel === "SAFE" ? "NO HEURISTIC MATCHES" : riskLevel.replace(/_/g, " ")}
              </Badge>
            </div>

            {/* Linear Progress Bar for Risk */}
            <div className="w-full bg-cyber-bg-tertiary h-1.5 overflow-hidden border border-cyber-border">
              <div
                className={`h-full transition-all duration-500 ${getProgressBarColor()}`}
                style={{ width: `${Math.min(100, Math.max(5, riskScore))}%` }}
              />
            </div>

            {riskScore === 0 && (
              <p className="text-[10px] font-mono text-cyber-text-dim leading-tight pt-1">
                No suspicious patterns were matched by the current rule set. This does not establish that the message is safe.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

