"use client";

import * as React from "react";
import {
  FileCode,
  ShieldCheck,
  AlertTriangle,
  Info,
  Layers,
  CheckCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { MessageIndicator } from "@/types/messages";

interface MessageEvidenceListProps {
  indicators: MessageIndicator[];
}

export function MessageEvidenceList({ indicators }: MessageEvidenceListProps) {
  const hasIndicators = indicators && indicators.length > 0;

  const getSeverityVariant = (severity: number) => {
    if (severity >= 80) return "critical";
    if (severity >= 60) return "high";
    if (severity >= 35) return "medium";
    return "low";
  };

  const getTypeLabel = (type: string) => {
    switch (type) {
      case "pattern_match":
        return "HEURISTIC PATTERN";
      case "urls_detected":
        return "LINK EXTRACTION";
      case "impersonation":
        return "ENTITY IMPERSONATION";
      default:
        return type.toUpperCase();
    }
  };

  return (
    <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-cyber-border pb-3">
        <div className="flex items-center gap-2">
          <FileCode className="h-4 w-4 text-cyber-accent" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
            DETERMINISTIC EVIDENCE & MATCHED PATTERNS
          </h3>
        </div>
        <span className="text-[10px] font-mono text-cyber-text-dim">
          {hasIndicators ? `${indicators.length} EVIDENCE RECORDS` : "ZERO SIGNATURES MATCHED"}
        </span>
      </div>

      {/* Guidance Notice */}
      <div className="p-3 bg-cyber-bg-secondary border border-cyber-border text-[11px] font-mono text-cyber-text-dim flex items-start gap-2">
        <Info className="h-3.5 w-3.5 text-cyber-accent shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          The records below represent deterministic regex rules, scam taxonomy matches, and lexical patterns
          triggered by the message content. Findings are derived without predictive machine learning models.
        </p>
      </div>

      {/* Indicators List */}
      {hasIndicators ? (
        <div className="divide-y divide-cyber-border font-mono">
          {indicators.map((ind, idx) => (
            <div
              key={idx}
              className="py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-cyber-bg-secondary px-2 transition-colors"
            >
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={getSeverityVariant(ind.severity)} className="text-[9px]">
                    SEV: {ind.severity}
                  </Badge>
                  <Badge variant="outline" className="text-[9px]">
                    {getTypeLabel(ind.type)}
                  </Badge>
                  {ind.scam_type && (
                    <span className="text-[10px] text-cyber-accent bg-cyber-bg-secondary px-1.5 py-0.5 border border-cyber-border">
                      {ind.scam_type}
                    </span>
                  )}
                </div>

                <div className="text-xs sm:text-sm font-medium text-cyber-text-primary pt-0.5">
                  {ind.description}
                </div>

                {ind.matched_snippet && (
                  <div className="text-[11px] text-cyber-text-muted bg-cyber-bg p-1.5 border border-cyber-border mt-1">
                    Matched text: <code className="text-cyber-text-secondary">{ind.matched_snippet}</code>
                  </div>
                )}
              </div>

              <div className="text-right shrink-0">
                <span className="text-[10px] uppercase text-cyber-text-dim">RULE SEVERITY</span>
                <div className="text-xs font-semibold text-cyber-text-secondary">
                  {ind.severity} / 100
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="p-6 text-center space-y-2 bg-cyber-bg-secondary border border-cyber-border font-mono">
          <ShieldCheck className="h-8 w-8 text-cyber-threat-secure mx-auto" />
          <h4 className="text-sm font-semibold text-cyber-text-primary">
            No Adverse Heuristic Indicators Triggered
          </h4>
          <p className="text-xs text-cyber-text-dim max-w-md mx-auto leading-relaxed">
            The message body did not match any active scam signatures, urgent OTP solicitations, or
            impersonation keywords in the current rule library.
          </p>
          <div className="text-[10px] text-cyber-text-dim pt-2 border-t border-cyber-border/60 max-w-lg mx-auto">
            Note: Rule-based heuristic pattern matching cannot detect all sophisticated social engineering.
            Always confirm unexpected requests through verified, out-of-band channels.
          </div>
        </div>
      )}
    </div>
  );
}

