"use client";

import * as React from "react";
import { ListChecks, CheckCircle2, AlertOctagon } from "lucide-react";

interface MessageRecommendationsProps {
  recommendedActions: string[];
  riskLevel: string;
}

export function MessageRecommendations({
  recommendedActions,
  riskLevel,
}: MessageRecommendationsProps) {
  const hasActions = recommendedActions && recommendedActions.length > 0;
  const isHighRisk = riskLevel === "CRITICAL" || riskLevel === "HIGH_RISK";

  return (
    <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-cyber-border pb-3">
        <div className="flex items-center gap-2">
          <ListChecks className="h-4 w-4 text-cyber-accent" />
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
            RECOMMENDED SOC OPERATIONAL ACTIONS
          </h3>
        </div>
        <span className="text-[10px] font-mono text-cyber-text-dim">
          INCIDENT RESPONSE PROTOCOL
        </span>
      </div>

      {hasActions ? (
        <ul className="space-y-2.5 font-mono text-xs">
          {recommendedActions.map((action, idx) => (
            <li
              key={idx}
              className={`flex items-start gap-2.5 p-3 border leading-relaxed ${
                isHighRisk && idx === 0
                  ? "bg-cyber-threat-critical/10 border-cyber-threat-critical/40 text-cyber-text-primary font-medium"
                  : "bg-cyber-bg-secondary border border-cyber-border text-cyber-text-secondary"
              }`}
            >
              {isHighRisk && idx === 0 ? (
                <AlertOctagon className="h-4 w-4 text-cyber-threat-critical shrink-0 mt-0.5" />
              ) : (
                <CheckCircle2 className="h-3.5 w-3.5 text-cyber-accent shrink-0 mt-0.5" />
              )}
              <span className="text-[11px] sm:text-xs">{action}</span>
            </li>
          ))}
        </ul>
      ) : (
        <div className="text-xs font-mono text-cyber-text-dim italic">
          No specialized operational actions recommended for this message.
        </div>
      )}
    </div>
  );
}

