"use client";

import * as React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  GitFork,
  Radio,
  FileCode,
  Info,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { ScanComponentDetail } from "@/types/scanner";

interface ScanComponentCardProps {
  id: string;
  name: string;
  description: string;
  detail?: ScanComponentDetail;
}

const COMPONENT_ICONS: Record<string, React.ElementType> = {
  threat_intelligence: Radio,
  phishing_malware: ShieldAlert,
  domain_reputation: ShieldCheck,
  url_patterns: FileCode,
  ssl_tls: Lock,
  redirect_analysis: GitFork,
};

export function ScanComponentCard({ id, name, description, detail }: ScanComponentCardProps) {
  const [expandedDetails, setExpandedDetails] = React.useState(false);
  const IconComponent = COMPONENT_ICONS[id] || ShieldAlert;

  if (!detail) {
    return (
      <div className="border border-cyber-border bg-cyber-bg-surface p-4 flex flex-col justify-between opacity-60">
        <div className="flex items-center gap-2">
          <IconComponent className="h-4 w-4 text-cyber-text-dim" />
          <h4 className="font-mono text-xs font-semibold text-cyber-text-muted uppercase">{name}</h4>
        </div>
        <div className="text-[11px] font-mono text-cyber-text-dim mt-2">
          Telemetry inactive for this subsystem.
        </div>
      </div>
    );
  }

  const confidence = (detail.confidence || "LOW").toUpperCase();
  const findingType = (detail.finding_type || "UNKNOWN").toUpperCase();
  const isUnavailable = confidence === "UNAVAILABLE" || detail.score === null;

  const getFindingVariant = (type: string) => {
    switch (type) {
      case "CONFIRMED_THREAT":
      case "CRITICAL_THREAT":
        return "critical";
      case "HEURISTIC_HIGH_RISK":
      case "SUSPICIOUS_INDICATOR":
        return "high";
      case "HEURISTIC_ASSESSMENT":
        return "medium";
      case "NO_KNOWN_DETECTION":
        return "secure";
      case "UNABLE_TO_VERIFY":
      default:
        return "outline";
    }
  };

  const getConfidenceVariant = (conf: string) => {
    switch (conf) {
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

  const hasDetails = detail.details && Object.keys(detail.details).length > 0;
  const evidenceList = Array.isArray(detail.evidence) ? detail.evidence : [];

  return (
    <div className="glass-panel border border-cyber-border-strong hover:border-cyber-accent/60 transition-colors flex flex-col justify-between p-4 space-y-4 rounded-xs relative group">
      {/* Corner Monolithic Framing */}
      <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t border-l border-cyber-accent/80" />
      <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b border-r border-cyber-accent/80" />

      {/* Header */}
      <div className="space-y-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-cyber-bg-secondary border border-cyber-border text-cyber-accent">
              <IconComponent className="h-3.5 w-3.5" />
            </div>
            <div>
              <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                {name}
              </h4>
              <p className="text-[10px] text-cyber-text-dim">{description}</p>
            </div>
          </div>

          {/* Subsystem Score */}
          <div className="text-right shrink-0">
            {detail.score !== null && detail.score !== undefined ? (
              <div className="font-mono text-sm font-bold text-cyber-text-primary flex items-baseline justify-end gap-1">
                <span
                  className={
                    detail.score > 50
                      ? "text-cyber-threat-critical"
                      : detail.score > 20
                      ? "text-cyber-threat-medium"
                      : "text-cyber-threat-secure"
                  }
                >
                  {detail.score}
                </span>
                <span className="text-[10px] font-normal text-cyber-text-dim">/100</span>
              </div>
            ) : (
              <span className="text-[11px] font-mono text-cyber-text-dim">N/A</span>
            )}
          </div>
        </div>

        {/* Badges strip: Finding Type & Confidence */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1">
          <Badge variant={getFindingVariant(findingType)} className="text-[9px]">
            {findingType.replace(/_/g, " ")}
          </Badge>
          <Badge variant={getConfidenceVariant(confidence)} className="text-[9px]">
            CONF: {confidence}
          </Badge>
        </div>
      </div>

      {/* Evidence & Findings */}
      <div className="space-y-2 pt-2 border-t border-cyber-border">
        <div className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim">
          OBSERVED EVIDENCE
        </div>

        {evidenceList.length > 0 ? (
          <ul className="space-y-1.5 text-xs font-mono">
            {evidenceList.map((item, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2 text-[11px] text-cyber-text-secondary leading-relaxed"
              >
                <span className="text-cyber-accent/60 mt-0.5">•</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        ) : isUnavailable || confidence === "UNAVAILABLE" || findingType === "UNABLE_TO_VERIFY" ? (
          <div className="text-[11px] font-mono text-cyber-text-dim italic">
            Subsystem offline or external provider unconfigured. No verification performed.
          </div>
        ) : (
          <div className="text-[11px] font-mono text-cyber-text-dim italic">
            No adverse indicators recorded for this vector.
          </div>
        )}

        {/* Specific notification for unconfigured threat intelligence */}
        {id === "threat_intelligence" && isUnavailable && (
          <div className="mt-2 p-2 bg-cyber-bg-secondary border border-cyber-border text-[10px] font-mono text-cyber-text-muted leading-relaxed">
            <span className="text-cyber-threat-medium font-semibold uppercase">FEED OFFLINE:</span> External API keys (VirusTotal/GSB/URLhaus) are unconfigured. This vector is marked UNAVAILABLE and excluded from the composite risk score.
          </div>
        )}

        {/* Expandable Technical Details if available */}
        {hasDetails && (
          <div className="pt-2">
            <button
              type="button"
              onClick={() => setExpandedDetails(!expandedDetails)}
              className="flex items-center gap-1 text-[10px] font-mono text-cyber-text-muted hover:text-cyber-accent transition-colors"
            >
              {expandedDetails ? (
                <>
                  <ChevronUp className="h-3 w-3" /> Hide Subsystem Metrics
                </>
              ) : (
                <>
                  <ChevronDown className="h-3 w-3" /> View Subsystem Metrics
                </>
              )}
            </button>

            {expandedDetails && (
              <pre className="mt-2 p-2 bg-cyber-bg-secondary border border-cyber-border text-[10px] font-mono text-cyber-text-secondary overflow-x-auto">
                {JSON.stringify(detail.details, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

