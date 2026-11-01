"use client";

import * as React from "react";
import {
  AlertTriangle,
  RefreshCw,
  ServerOff,
  RotateCcw,
  FileWarning,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { MessageApiError } from "@/types/messages";

interface MessageAnalysisErrorProps {
  error: MessageApiError;
  onRetry: () => void;
  onReset: () => void;
}

export function MessageAnalysisError({
  error,
  onRetry,
  onReset,
}: MessageAnalysisErrorProps) {
  const isNetwork = error.status === 0;
  const isTooLong = error.isTooLong;
  const isBlank = error.isBlank;

  return (
    <div className="border border-cyber-border-strong bg-cyber-bg-surface p-6 lg:p-8 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 border-b border-cyber-border pb-4">
        <div className="flex items-start gap-3">
          <div
            className={`p-2.5 border ${
              isTooLong || isBlank
                ? "bg-cyber-threat-high/10 border-cyber-threat-high/40 text-cyber-threat-high"
                : isNetwork
                ? "bg-cyber-threat-critical/10 border-cyber-threat-critical/40 text-cyber-threat-critical"
                : "bg-cyber-threat-high/10 border-cyber-threat-high/40 text-cyber-threat-high"
            }`}
          >
            {isNetwork ? (
              <ServerOff className="h-6 w-6" />
            ) : isTooLong || isBlank ? (
              <FileWarning className="h-6 w-6" />
            ) : (
              <AlertTriangle className="h-6 w-6" />
            )}
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Badge
                variant={isNetwork ? "critical" : "high"}
                className="text-[10px]"
              >
                {isNetwork
                  ? "BUS OFFLINE"
                  : error.status > 0
                  ? `HTTP ${error.status} ERROR`
                  : "EXCEPTION"}
              </Badge>
              <span className="text-[10px] font-mono text-cyber-text-dim">
                {"//"} MESSAGE_ANALYZER_EXCEPTION
              </span>
            </div>

            <h3 className="font-mono text-base font-semibold text-cyber-text-primary">
              {isTooLong
                ? "Message Exceeds Analysis Boundary"
                : isBlank
                ? "Empty Input Rejected"
                : isNetwork
                ? "FastAPI Bus Unreachable"
                : "Analysis Service Error"}
            </h3>
          </div>
        </div>

        <div className="hidden sm:block text-right">
          <span className="text-[10px] font-mono uppercase text-cyber-text-dim">
            SUB-BUS STATUS
          </span>
          <div className="text-xs font-mono text-cyber-threat-high font-semibold">
            EXECUTION HALTED
          </div>
        </div>
      </div>

      {/* Message and detail */}
      <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2">
        <p className="font-mono text-xs sm:text-sm text-cyber-text-primary leading-relaxed">
          {error.message}
        </p>

        {error.detail && error.detail !== error.message && (
          <div className="pt-2 border-t border-cyber-border">
            <div className="text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider mb-1">
              RAW DIAGNOSTIC TELEMETRY:
            </div>
            <code className="text-[11px] font-mono text-cyber-text-muted break-all">
              {error.detail}
            </code>
          </div>
        )}
      </div>

      {/* Guidance */}
      <div className="p-4 bg-cyber-bg-tertiary border border-cyber-border space-y-2 font-mono text-xs">
        <div className="text-[10px] text-cyber-accent uppercase tracking-wider font-semibold">
          ANALYST GUIDANCE & PROTOCOL:
        </div>
        <ul className="space-y-1.5 text-cyber-text-secondary text-[11px]">
          {isTooLong ? (
            <>
              <li>• The backend message analyzer accepts up to 10,000 characters per evaluation request.</li>
              <li>• Truncate headers, disclaimer footers, or analyze suspicious segments independently.</li>
            </>
          ) : isBlank ? (
            <>
              <li>• Paste email bodies, SMS transcripts, or suspicious message text before dispatching.</li>
            </>
          ) : isNetwork ? (
            <>
              <li>• Verify that the FastAPI backend service is running on http://localhost:8000.</li>
              <li>• Check that endpoint POST /api/v1/messages/analyze is active and accepting requests.</li>
            </>
          ) : (
            <>
              <li>• Verify message character encoding is valid UTF-8.</li>
              <li>• Review backend server logs for internal regex or analysis exceptions.</li>
            </>
          )}
        </ul>
      </div>

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3 pt-2">
        <Button
          type="button"
          variant="arctic"
          size="sm"
          onClick={onRetry}
          className="gap-2 font-mono uppercase text-xs"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Retry Analysis</span>
        </Button>

        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onReset}
          className="gap-2 font-mono uppercase text-xs"
        >
          <RotateCcw className="h-3.5 w-3.5" />
          <span>Clear & Reset</span>
        </Button>
      </div>
    </div>
  );
}

