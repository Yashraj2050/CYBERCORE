"use client";

import * as React from "react";
import { ShieldAlert, AlertTriangle, RefreshCw, XCircle, Terminal, Server } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { IpDomainApiError } from "@/types/ip-domain";

interface IpDomainErrorProps {
  error: IpDomainApiError;
  onRetry: () => void;
  onClear: () => void;
}

export function IpDomainError({ error, onRetry, onClear }: IpDomainErrorProps) {
  const isSsrf = Boolean(error.isSecurityRestriction);

  return (
    <div className="border border-cyber-border-strong bg-cyber-bg-surface p-6 space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div className="flex items-center gap-3">
          <div
            className={`p-2 border ${
              isSsrf
                ? "bg-cyber-threat-critical/10 border-cyber-threat-critical text-cyber-threat-critical"
                : "bg-cyber-threat-high/10 border-cyber-threat-high text-cyber-threat-high"
            }`}
          >
            {isSsrf ? <ShieldAlert className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <Badge variant={isSsrf ? "critical" : "high"} className="text-[10px]">
                {error.status ? `HTTP ${error.status}` : "NETWORK FAILURE"}
              </Badge>
              {isSsrf && (
                <Badge variant="outline" className="text-[10px] text-cyber-accent">
                  SSRF ENFORCEMENT
                </Badge>
              )}
            </div>
            <h3 className="text-base font-mono font-bold text-cyber-text-primary pt-1">
              {error.title}
            </h3>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onClear}
            className="text-xs font-mono h-8"
          >
            CLEAR
          </Button>
          <Button
            type="button"
            variant="default"
            size="sm"
            onClick={onRetry}
            className="text-xs font-mono h-8 gap-1.5"
          >
            <RefreshCw className="h-3 w-3" />
            RETRY INVESTIGATION
          </Button>
        </div>
      </div>

      {/* Error Message Details */}
      <div className="space-y-4">
        <div className="p-4 bg-cyber-bg-secondary border border-cyber-border font-mono text-xs space-y-2">
          <div className="text-[10px] uppercase text-cyber-text-dim tracking-wider flex items-center gap-1.5">
            <Terminal className="h-3 w-3 text-cyber-accent" />
            <span>ENGINE EXECUTION DIAGNOSTIC</span>
          </div>
          <p className="text-cyber-text-primary leading-relaxed font-semibold">
            {error.message}
          </p>
          {error.detail && error.detail !== error.message && (
            <p className="text-cyber-text-secondary text-[11px] pt-1 border-t border-cyber-border/60">
              Raw Detail: <code className="text-cyber-accent">{error.detail}</code>
            </p>
          )}
        </div>

        {/* Informational Guidance */}
        {isSsrf ? (
          <div className="p-4 bg-cyber-bg border border-cyber-border space-y-2 text-xs font-mono text-cyber-text-secondary">
            <div className="text-[10px] text-cyber-threat-critical uppercase font-semibold tracking-wider">
              POLICY SPECIFICATION: PRIVATE NETWORK DEFENSE
            </div>
            <p className="leading-relaxed">
              CYBERCORE enforces strict Server-Side Request Forgery (SSRF) boundary protections. The submitted target
              resolves to a private RFC1918 range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback interface
              (127.0.0.1, ::1), link-local subnet, or cloud metadata address (169.254.169.254).
            </p>
            <p className="text-cyber-text-dim text-[11px]">
              Submitting internal addresses to public intelligence endpoints is prohibited to prevent host network mapping.
            </p>
          </div>
        ) : error.status === 0 || error.isTimeout ? (
          <div className="p-4 bg-cyber-bg border border-cyber-border space-y-2 text-xs font-mono text-cyber-text-secondary">
            <div className="text-[10px] text-cyber-accent uppercase font-semibold tracking-wider flex items-center gap-1.5">
              <Server className="h-3 w-3" />
              <span>COMMUNICATION RESOLUTION GUIDANCE</span>
            </div>
            <ul className="space-y-1 text-[11px] list-disc list-inside text-cyber-text-dim">
              <li>Verify the FastAPI backend service is active and listening on port 8000.</li>
              <li>Check local firewall or Docker network bridges for UDP port 53 DNS connectivity.</li>
              <li>Verify that outbound HTTPS access to <code className="text-cyber-text-secondary">https://rdap.org</code> is unblocked.</li>
            </ul>
          </div>
        ) : null}
      </div>
    </div>
  );
}

