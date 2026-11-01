"use client";

import * as React from "react";
import {
  Flame,
  Shield,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  FileSearch,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { dashboardService } from "@/lib/api/services/dashboard";
import type { ThreatFeedCampaign } from "@/types/dashboard";

export default function ThreatIntelligencePage() {
  const [campaigns, setCampaigns] = React.useState<ThreatFeedCampaign[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const loadFeed = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await dashboardService.getThreatFeed();
      setCampaigns(data.active_campaigns || []);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load threat intelligence"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    loadFeed();
  }, [loadFeed]);

  return (
    <PageContainer>
      <PageHeader
        editorialTag="CURATED THREAT INTELLIGENCE // REFERENCE FEED"
        title="Threat Intelligence"
        description="Curated threat intelligence highlights, verified social engineering tactics, credential lure indicators, and recommended proactive mitigation playbooks."
        badge={
          <Badge variant="arctic" radius="xs" dot>
            CURATED FEED
          </Badge>
        }
        actions={
          <Button
            variant="monolithic"
            size="sm"
            onClick={loadFeed}
            disabled={loading}
            className="gap-1.5"
          >
            <RefreshCw
              className={`h-3 w-3 ${loading ? "animate-spin text-cyber-accent" : "text-cyber-text-dim"}`}
            />
            <span>REFRESH FEED</span>
          </Button>
        }
      />

      {/* Campaigns Matrix */}
      <div className="space-y-4">
        {loading ? (
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-32 bg-cyber-bg-secondary border border-cyber-border rounded-xs animate-pulse"
              />
            ))}
          </div>
        ) : error ? (
          <div className="p-8 border border-cyber-threat-critical-border bg-cyber-threat-critical-bg rounded-xs text-center space-y-2 text-xs font-mono">
            <p className="text-cyber-threat-critical">
              CAMPAIGN FEED OFFLINE: {error}
            </p>
            <Button size="xs" variant="outline" onClick={loadFeed}>
              Retry Connection
            </Button>
          </div>
        ) : campaigns.length === 0 ? (
          <div className="p-12 border border-cyber-border bg-cyber-bg-secondary rounded-xs text-center text-xs font-mono text-cyber-text-dim">
            No active threat campaigns currently cataloged in the intelligence cache.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {campaigns.map((item, idx) => {
              const isCritical = item.severity === "CRITICAL";
              const isHigh = item.severity === "HIGH";

              return (
                <div
                  key={idx}
                  className="p-5 glass-panel border border-cyber-border rounded-xs space-y-4 flex flex-col justify-between hover:border-cyber-accent/50 transition-colors relative group"
                >
                  {/* Corner Monolithic Framing */}
                  <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
                  <span className="pointer-events-none absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
                  <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent opacity-75 group-hover:opacity-100" />
                  <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyber-accent opacity-75 group-hover:opacity-100" />

                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-xs font-mono font-semibold text-cyber-text-primary leading-tight">
                        {item.title}
                      </span>
                      <Badge
                        variant={isCritical ? "critical" : isHigh ? "high" : "medium"}
                        radius="xs"
                        dot
                      >
                        {item.severity}
                      </Badge>
                    </div>

                    <div className="space-y-1.5">
                      <span className="text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider block">
                        Observed Indicators:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {item.indicators.map((ind, i) => (
                          <span
                            key={i}
                            className="text-[9px] font-mono bg-cyber-bg text-cyber-accent px-1.5 py-0.5 border border-cyber-border rounded-none"
                          >
                            {ind}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-1 pt-2 border-t border-cyber-border/40">
                      <span className="text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider block">
                        Mitigation Directive:
                      </span>
                      <p className="text-xs text-cyber-text-secondary leading-relaxed font-sans">
                        {item.recommendation}
                      </p>
                    </div>
                  </div>

                  <div className="pt-2 text-[10px] font-mono text-cyber-text-dim flex items-center justify-between border-t border-cyber-border/40">
                    <span>SOURCE: CYBERCORE FEED</span>
                    <span className="text-emerald-400">ACTIVE RULESET</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </PageContainer>
  );
}

