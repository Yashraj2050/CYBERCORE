"use client";

import * as React from "react";
import {
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  ServerOff,
  WifiOff,
  HelpCircle,
  RotateCcw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { ScanApiError } from "@/types/scanner";

interface ScanErrorStateProps {
  error: ScanApiError;
  onRetry: () => void;
  onReset: () => void;
  targetUrl?: string;
}

export function ScanErrorState({
  error,
  onRetry,
  onReset,
  targetUrl,
}: ScanErrorStateProps) {
  const isSsrf = error.isSsrf;
  const isTimeout = error.isTimeout;
  const isNetwork = error.status === 0;

  return (
    <div className="border border-cyber-border-strong bg-cyber-bg-surface p-6 lg:p-8 space-y-6">
      {/* Header with error classification */}
      <div className="flex items-start justify-between gap-4 border-b border-cyber-border pb-4">
        <div className="flex items-start gap-3">
          <div
            className={`p-2.5 border ${
              isSsrf
                ? "bg-cyber-threat-critical/10 border-cyber-threat-critical/40 text-cyber-threat-critical"
                : "bg-cyber-threat-high/10 border-cyber-threat-high/40 text-cyber-threat-high"
            }`}
          >
            {isSsrf ? (
              <ShieldAlert className="h-6 w-6" />
            ) : isNetwork || isTimeout ? (
              <ServerOff className="h-6 w-6" />
            ) : (
              <AlertTriangle className="h-6 w-6" />
            )}
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Badge
                variant={isSsrf ? "critical" : "high"}
                className="text-[10px]"
              >
                {isSsrf
                  ? "SSRF DEFENSE ACTIVE"
                  : error.status > 0
                  ? `HTTP ${error.status} ERROR`
                  : "NETWORK EXCEPTION"}
              </Badge>
              {targetUrl && (
                <span className="text-[10px] font-mono text-cyber-text-dim truncate max-w-xs">
                  {"//"} {targetUrl}
                </span>
              )}
            </div>
            <h3 className="font-mono text-base font-semibold text-cyber-text-primary">
              {isSsrf ? "Server-Side Request Forgery Defense Block" : "Target Analysis Failed"}
            </h3>
          </div>
        </div>

        <div className="hidden sm:block text-right">
          <span className="text-[10px] font-mono uppercase text-cyber-text-dim">
            SUB-BUS STATUS
          </span>
          <div className="text-xs font-mono text-cyber-threat-high font-semibold">
            EXECUTION REJECTED
          </div>
        </div>
      </div>

      {/* Primary Message */}
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

      {/* Remediation & Context Details */}
      <div className="p-4 bg-cyber-bg-tertiary border border-cyber-border space-y-2 font-mono text-xs">
        <div className="text-[10px] text-cyber-accent uppercase tracking-wider font-semibold">
          ANALYST GUIDANCE & PROTOCOL:
        </div>
        <ul className="space-y-1.5 text-cyber-text-secondary text-[11px]">
          {isSsrf ? (
            <>
              <li>
                • CYBERCORE explicitly disallows scanning localhost, loopback (127.0.0.1/8, ::1),
                and private RFC 1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
              </li>
              <li>
                • This security policy protects internal services and metadata endpoints from
                unauthorized inspection.
              </li>
              <li>• To continue testing, select an external public target (e.g. 1.1.1.1 or 8.8.8.8).</li>
            </>
          ) : isNetwork ? (
            <>
              <li>• Ensure the Python FastAPI backend service is active and reachable.</li>
              <li>• Verify that CORS and network firewalls permit communication with the API.</li>
            </>
          ) : isTimeout ? (
            <>
              <li>• Upstream target failed to resolve or respond within the 30-second inspection budget.</li>
              <li>• Verify if the domain is currently under a denial of service or behind heavy filtering.</li>
            </>
          ) : (
            <>
              <li>• Check that the destination hostname exists in public DNS and is syntactically valid.</li>
              <li>• Ensure scheme is explicitly specified (e.g. https://domain.com).</li>
            </>
          )}
        </ul>
      </div>

      {/* Action Controls */}
      <div className="flex flex-wrap items-center gap-3 pt-2">
        <Button
          type="button"
          variant="arctic"
          size="sm"
          onClick={onRetry}
          className="gap-2 font-mono uppercase text-xs"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Retry Inspection</span>
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
