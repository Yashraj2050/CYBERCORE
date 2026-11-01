"use client";

import * as React from "react";
import Link from "next/link";
import { ShieldAlert, ArrowUpRight, Clock, FileText, Globe, MessageSquare } from "lucide-react";
import type { RecentScanItem } from "@/types/dashboard";
import { Badge } from "@/components/ui/badge";

interface RecentInvestigationsProps {
  scans: RecentScanItem[];
  loading: boolean;
  error: string | null;
}

const typeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  URL: Globe,
  MESSAGE: MessageSquare,
  FILE: FileText,
};

export function RecentInvestigations({
  scans,
  loading,
  error,
}: RecentInvestigationsProps) {
  if (loading) {
    return (
      <div className="glass-panel p-5 rounded-xs space-y-3 relative">
        <div className="h-4 w-44 bg-cyber-bg-surface animate-pulse" />
        <div className="space-y-2">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="h-10 bg-cyber-bg-surface/60 rounded-none animate-pulse"
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="glass-panel p-5 rounded-xs space-y-4 relative group border border-cyber-border">
      {/* Corner Monolithic Framing */}
      <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

      <div className="flex items-center justify-between border-b border-cyber-border/60 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-mono text-cyber-accent tracking-widest">{"// ARCHIVE"}</span>
          <h2 className="text-xs font-mono font-semibold tracking-tactical uppercase text-cyber-text-primary">
            Recent Investigation Samples
          </h2>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            ({scans.length} records)
          </span>
        </div>

        <Link
          href="/investigations"
          className="text-[10px] font-mono text-cyber-accent hover:underline flex items-center gap-1 uppercase tracking-wider"
        >
          Sample Archive
          <ArrowUpRight className="h-3 w-3" />
        </Link>
      </div>

      {error ? (
        <div className="py-6 text-center text-xs font-mono text-cyber-threat-critical/80">
          Telemetry unavailable: {error}
        </div>
      ) : scans.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-cyber-text-dim">
          No investigation samples cataloged on this node.
        </div>
      ) : (
        <div className="divide-y divide-cyber-border/40 overflow-x-auto">
          {scans.map((scan) => {
            const Icon = typeIcons[scan.type] || Globe;
            const isCritical = scan.risk_level === "CRITICAL" || scan.risk_score >= 70;
            const isSafe = scan.risk_level === "SAFE" || scan.risk_score < 20;

            return (
              <div
                key={scan.id}
                className="py-2.5 flex items-center justify-between gap-3 text-xs font-mono hover:bg-cyber-bg-surface/50 px-1.5 transition-colors rounded-xs"
              >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <div className="flex h-7 w-7 items-center justify-center border border-cyber-border bg-cyber-bg rounded-xs shrink-0">
                    <Icon className="h-3.5 w-3.5 text-cyber-accent" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-cyber-text-primary font-medium truncate">
                      {scan.target}
                    </p>
                    <p className="text-[10px] text-cyber-text-dim truncate">
                      {scan.verdict}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 shrink-0">
                  <Badge
                    variant={isCritical ? "critical" : isSafe ? "secure" : "medium"}
                    radius="xs"
                    dot
                  >
                    {scan.risk_level} ({scan.risk_score})
                  </Badge>
                  <span className="hidden sm:inline text-[10px] text-cyber-text-dim">
                    {new Date(scan.timestamp).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
