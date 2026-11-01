"use client";

import * as React from "react";
import { MessageAnalysisHeader } from "./message-analysis-header";
import { MessageThreatIndicators } from "./message-threat-indicators";
import { MessageEvidenceList } from "./message-evidence-list";
import { MessageRecommendations } from "./message-recommendations";
import { Code, Copy, Check, Download, ChevronDown, ChevronUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { MessageAnalyzeResult } from "@/types/messages";

interface MessageAnalysisResultsProps {
  result: MessageAnalyzeResult;
}

export function MessageAnalysisResults({ result }: MessageAnalysisResultsProps) {
  const [isOpenJson, setIsOpenJson] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const jsonString = React.useMemo(() => {
    return JSON.stringify(result, null, 2);
  }, [result]);

  const byteLength = React.useMemo(() => {
    return new Blob([jsonString]).size;
  }, [jsonString]);

  const copyToClipboard = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJson = () => {
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `message_analysis_${result.message_hash ? result.message_hash.slice(0, 12) : "telemetry"}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8 animate-in fade-in-50 duration-300">
      {/* 1. Analysis Header & Monolithic Score Card */}
      <MessageAnalysisHeader result={result} />

      {/* 2. Threat Indicators (Tactics, Impersonation, URLs) */}
      <MessageThreatIndicators
        manipulationTactics={result.manipulation_tactics || []}
        impersonationTargets={result.impersonation_targets || []}
        urlsFound={result.urls_found || []}
      />

      {/* 3. Deterministic Evidence & Matched Patterns List */}
      <MessageEvidenceList indicators={result.indicators || []} />

      {/* 4. SOC Recommendations */}
      <MessageRecommendations
        recommendedActions={result.recommended_actions || []}
        riskLevel={result.risk_level || "SAFE"}
      />

      {/* 5. Collapsible Raw OpenAPI Telemetry */}
      <div className="border border-cyber-border-strong bg-cyber-bg-surface">
        <div className="flex items-center justify-between p-4 bg-cyber-bg-secondary border-b border-cyber-border">
          <button
            type="button"
            onClick={() => setIsOpenJson(!isOpenJson)}
            className="flex items-center gap-2 text-left font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary hover:text-cyber-accent transition-colors"
          >
            <Code className="h-4 w-4 text-cyber-accent" />
            <span>RAW OPENAPI TELEMETRY</span>
            <span className="text-[10px] text-cyber-text-dim lowercase font-normal ml-2">
              ({byteLength} bytes)
            </span>
            {isOpenJson ? (
              <ChevronUp className="h-3.5 w-3.5 text-cyber-text-muted ml-1" />
            ) : (
              <ChevronDown className="h-3.5 w-3.5 text-cyber-text-muted ml-1" />
            )}
          </button>

          {isOpenJson && (
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={copyToClipboard}
                className="h-7 px-2.5 text-[10px] font-mono uppercase tracking-wider"
              >
                {copied ? (
                  <>
                    <Check className="h-3 w-3 text-cyber-threat-secure mr-1" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3 mr-1" /> Copy JSON
                  </>
                )}
              </Button>

              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={downloadJson}
                className="h-7 px-2.5 text-[10px] font-mono uppercase tracking-wider"
              >
                <Download className="h-3 w-3 mr-1" /> Export
              </Button>
            </div>
          )}
        </div>

        {isOpenJson && (
          <div className="p-4 bg-cyber-bg">
            <pre className="max-h-96 overflow-x-auto overflow-y-auto p-4 bg-cyber-bg-secondary border border-cyber-border text-xs font-mono text-cyber-text-secondary leading-relaxed select-all">
              {jsonString}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

