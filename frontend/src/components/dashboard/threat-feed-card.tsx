"use client";

import * as React from "react";
import Link from "next/link";
import { Flame, ArrowUpRight, ShieldCheck, AlertTriangle } from "lucide-react";
import type { ThreatFeedCampaign } from "@/types/dashboard";
import { Badge } from "@/components/ui/badge";

interface ThreatFeedCardProps {
  campaigns: ThreatFeedCampaign[];
  loading: boolean;
  error: string | null;
}

export function ThreatFeedCard({
  campaigns,
  loading,
  error,
}: ThreatFeedCardProps) {
  if (loading) {
    return (
      <div className="glass-panel p-5 rounded-xs space-y-3 relative">
        <div className="h-4 w-36 bg-cyber-bg-surface animate-pulse" />
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 bg-cyber-bg-surface/50 rounded-xs animate-pulse" />
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
          <Flame className="h-4 w-4 text-cyber-accent" />
          <h2 className="text-xs font-mono font-semibold tracking-tactical uppercase text-cyber-text-primary">
            Curated Threat Intelligence
          </h2>
        </div>

        <Link
          href="/threat-intelligence"
          className="text-[10px] font-mono text-cyber-accent hover:underline flex items-center gap-1 uppercase tracking-wider"
        >
          Reference Intel
          <ArrowUpRight className="h-3 w-3" />
        </Link>
      </div>

      {error ? (
        <div className="py-6 text-center text-xs font-mono text-cyber-threat-critical/80">
          Campaign feed unavailable: {error}
        </div>
      ) : campaigns.length === 0 ? (
        <div className="py-8 text-center text-xs font-mono text-cyber-text-dim">
          No threat intelligence records currently cataloged in the reference cache.
        </div>
      ) : (
        <div className="space-y-3">
          {campaigns.map((item, idx) => (
            <div
              key={idx}
              className="p-3 bg-cyber-bg border border-cyber-border rounded-xs space-y-2 hover:border-cyber-border-strong transition-colors"
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-xs font-mono font-medium text-cyber-text-primary">
                  {item.title}
                </span>
                <Badge
                  variant={
                    item.severity === "CRITICAL"
                      ? "critical"
                      : item.severity === "HIGH"
                      ? "high"
                      : "medium"
                  }
                  radius="xs"
                >
                  {item.severity}
                </Badge>
              </div>

              {/* Indicators */}
              <div className="flex flex-wrap gap-1.5 pt-0.5">
                {item.indicators.map((ind, i) => (
                  <span
                    key={i}
                    className="text-[9px] font-mono bg-cyber-bg-surface text-cyber-text-dim px-1.5 py-0.5 border border-cyber-border/60 rounded-none uppercase"
                  >
                    {ind}
                  </span>
                ))}
              </div>

              {/* Recommendation */}
              <p className="text-[11px] text-cyber-text-secondary leading-snug font-sans">
                {item.recommendation}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
