"use client";

import * as React from "react";
import { ShieldCheck, ShieldAlert, Activity, Users, AlertOctagon, RefreshCw } from "lucide-react";
import type { DashboardStats } from "@/types/dashboard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface DashboardSummaryProps {
  stats: DashboardStats | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

export function DashboardSummary({
  stats,
  loading,
  error,
  onRefresh,
}: DashboardSummaryProps) {
  if (loading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="p-5 glass-panel rounded-xs space-y-3 animate-pulse relative"
          >
            <div className="h-3 w-20 bg-cyber-bg-surface rounded-none" />
            <div className="h-9 w-28 bg-cyber-bg-surface-elevated rounded-none" />
            <div className="h-2 w-32 bg-cyber-bg-surface rounded-none" />
          </div>
        ))}
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="p-4 border border-cyber-threat-critical-border bg-cyber-threat-critical-bg rounded-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2 text-cyber-threat-critical">
          <AlertOctagon className="h-4 w-4 shrink-0" />
          <span>BACKEND TELEMETRY OFFLINE: {error || "Unable to reach FastAPI service"}</span>
        </div>
        <Button
          size="xs"
          variant="outline"
          onClick={onRefresh}
          className="gap-1.5 border-cyber-threat-critical/40 text-cyber-threat-critical hover:bg-cyber-threat-critical/10"
        >
          <RefreshCw className="h-3 w-3" />
          RETRY BUS
        </Button>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
      {/* Metric 1: Safety Index */}
      <div className="glass-panel p-5 rounded-xs relative group border border-cyber-border hover:border-cyber-accent/60 transition-colors">
        {/* Monolithic 4-Corner Framing */}
        <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] font-mono text-cyber-accent tracking-widest">{"// 01"}</span>
            <span className="text-[10px] font-mono tracking-tactical uppercase text-cyber-text-dim font-medium">
              SAFETY INDEX
            </span>
          </div>
          <Badge variant={stats.safety_index >= 90 ? "secure" : "medium"} radius="xs">
            {stats.protection_status}
          </Badge>
        </div>

        <div className="flex items-baseline gap-2 my-2">
          <span className="text-3xl sm:text-4xl font-mono font-bold tracking-tight text-cyber-text-primary">
            {stats.safety_index}
          </span>
          <span className="text-xs font-mono text-cyber-text-dim">/ 100</span>
        </div>

        <div className="border-t border-cyber-border/40 pt-2 mt-2 flex items-center justify-between">
          <p className="text-[10px] text-cyber-text-dim font-mono truncate">
            Posture: <span className="text-cyber-text-secondary font-medium">{stats.system_status}</span>
          </p>
          <span className="text-[9px] font-mono text-cyber-text-dim uppercase tracking-wider">AGGREGATE</span>
        </div>
      </div>

      {/* Metric 2: Threats Intercepted */}
      <div className="glass-panel p-5 rounded-xs relative group border border-cyber-border hover:border-cyber-threat-critical/60 transition-colors">
        <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-threat-critical" />
        <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-threat-critical" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-threat-critical" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-threat-critical" />

        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] font-mono text-cyber-threat-critical tracking-widest">{"// 02"}</span>
            <span className="text-[10px] font-mono tracking-tactical uppercase text-cyber-text-dim font-medium">
              THREATS INTERCEPTED
            </span>
          </div>
          <Badge variant="critical" radius="xs" dot>
            {stats.threat_level}
          </Badge>
        </div>

        <div className="flex items-baseline gap-2 my-2">
          <span className="text-3xl sm:text-4xl font-mono font-bold tracking-tight text-cyber-threat-critical">
            {stats.threats_intercepted.toLocaleString()}
          </span>
        </div>

        <div className="border-t border-cyber-border/40 pt-2 mt-2 flex items-center justify-between">
          <p className="text-[10px] text-cyber-text-dim font-mono truncate">
            {stats.phishing_campaigns_detected} active phishing campaigns
          </p>
          <span className="text-[9px] font-mono text-cyber-threat-critical uppercase tracking-wider">BLOCKED</span>
        </div>
      </div>

      {/* Metric 3: Scans Today */}
      <div className="glass-panel p-5 rounded-xs relative group border border-cyber-border hover:border-cyber-accent/60 transition-colors">
        <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] font-mono text-cyber-accent tracking-widest">{"// 03"}</span>
            <span className="text-[10px] font-mono tracking-tactical uppercase text-cyber-text-dim font-medium">
              SCANS EXECUTED (24H)
            </span>
          </div>
          <Badge variant="arctic" radius="xs">
            TELEMETRY
          </Badge>
        </div>

        <div className="flex items-baseline gap-2 my-2">
          <span className="text-3xl sm:text-4xl font-mono font-bold tracking-tight text-cyber-accent">
            {stats.total_scans_today.toLocaleString()}
          </span>
        </div>

        <div className="border-t border-cyber-border/40 pt-2 mt-2 flex items-center justify-between">
          <p className="text-[10px] text-cyber-text-dim font-mono truncate">
            {stats.malware_signatures_verified} signatures verified
          </p>
          <span className="text-[9px] font-mono text-cyber-text-dim uppercase tracking-wider">PIPELINE</span>
        </div>
      </div>

      {/* Metric 4: Browser Extension Fleet */}
      <div className="glass-panel p-5 rounded-xs relative group border border-cyber-border hover:border-cyber-accent/60 transition-colors">
        <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5">
            <span className="text-[9px] font-mono text-cyber-accent tracking-widest">{"// 04"}</span>
            <span className="text-[10px] font-mono tracking-tactical uppercase text-cyber-text-dim font-medium">
              ACTIVE EXTENSION FLEET
            </span>
          </div>
          <Badge variant="monolithic" radius="xs">
            CLIENTS
          </Badge>
        </div>

        <div className="flex items-baseline gap-2 my-2">
          <span className="text-3xl sm:text-4xl font-mono font-bold tracking-tight text-cyber-text-primary">
            {stats.extension_active_users.toLocaleString()}
          </span>
        </div>

        <div className="border-t border-cyber-border/40 pt-2 mt-2 flex items-center justify-between">
          <p className="text-[10px] text-cyber-text-dim font-mono truncate">
            Real-time extension endpoints
          </p>
          <span className="text-[9px] font-mono text-cyber-threat-secure uppercase tracking-wider">SYNCED</span>
        </div>
      </div>
    </div>
  );
}
