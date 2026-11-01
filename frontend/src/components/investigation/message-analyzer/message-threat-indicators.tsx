"use client";

import * as React from "react";
import Link from "next/link";
import {
  Flame,
  UserX,
  Link2,
  ExternalLink,
  ShieldAlert,
  ArrowRight,
  ArrowUpRight,
  AlertCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface MessageThreatIndicatorsProps {
  manipulationTactics: string[];
  impersonationTargets: string[];
  urlsFound: string[];
}

function extractHostname(rawUrl: string): string | null {
  try {
    const candidate =
      rawUrl.startsWith("http://") || rawUrl.startsWith("https://")
        ? rawUrl
        : `http://${rawUrl}`;
    const parsed = new URL(candidate);
    return parsed.hostname || null;
  } catch {
    return null;
  }
}

export function MessageThreatIndicators({
  manipulationTactics,
  impersonationTargets,
  urlsFound,
}: MessageThreatIndicatorsProps) {
  const hasTactics = manipulationTactics && manipulationTactics.length > 0;
  const hasImpersonation = impersonationTargets && impersonationTargets.length > 0;
  const hasUrls = urlsFound && urlsFound.length > 0;

  const hostnames = React.useMemo(() => {
    if (!urlsFound || urlsFound.length === 0) return [];
    const set = new Set<string>();
    urlsFound.forEach((u) => {
      const h = extractHostname(u);
      if (h) set.add(h);
    });
    return Array.from(set);
  }, [urlsFound]);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {/* 1. Manipulation Tactics */}
      <div className="glass-panel border border-cyber-border-strong p-4 flex flex-col justify-between space-y-3 rounded-xs relative group">
        <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t border-l border-cyber-accent/80" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b border-r border-cyber-accent/80" />
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-cyber-bg-secondary border border-cyber-border text-cyber-threat-high">
              <Flame className="h-3.5 w-3.5" />
            </div>
            <div>
              <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                Manipulation Tactics
              </h4>
              <p className="text-[10px] text-cyber-text-dim">
                Psychological urgency and pressure signals
              </p>
            </div>
          </div>

          <div className="pt-2">
            {hasTactics ? (
              <div className="flex flex-wrap gap-1.5">
                {manipulationTactics.map((tactic, idx) => (
                  <Badge key={idx} variant="high" className="text-[10px] py-0.5">
                    {tactic}
                  </Badge>
                ))}
              </div>
            ) : (
              <div className="text-[11px] font-mono text-cyber-text-dim italic">
                No psychological manipulation tactics detected.
              </div>
            )}
          </div>
        </div>

        <div className="text-[10px] font-mono text-cyber-text-dim border-t border-cyber-border pt-2">
          {hasTactics ? `${manipulationTactics.length} tactic(s) active` : "Zero urgency heuristics matched"}
        </div>
      </div>

      {/* 2. Brand & Authority Impersonation */}
      <div className="glass-panel border border-cyber-border-strong p-4 flex flex-col justify-between space-y-3 rounded-xs relative group">
        <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t border-l border-cyber-threat-critical/80" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b border-r border-cyber-threat-critical/80" />
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-cyber-bg-secondary border border-cyber-border text-cyber-threat-critical">
              <UserX className="h-3.5 w-3.5" />
            </div>
            <div>
              <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                Brand Impersonation
              </h4>
              <p className="text-[10px] text-cyber-text-dim">
                Spoofed institutional or financial identities
              </p>
            </div>
          </div>

          <div className="pt-2">
            {hasImpersonation ? (
              <div className="flex flex-wrap gap-1.5">
                {impersonationTargets.map((target, idx) => (
                  <Badge key={idx} variant="critical" className="text-[10px] py-0.5">
                    {target}
                  </Badge>
                ))}
              </div>
            ) : (
              <div className="text-[11px] font-mono text-cyber-text-dim italic">
                No known brand impersonation signatures detected.
              </div>
            )}
          </div>
        </div>

        <div className="text-[10px] font-mono text-cyber-text-dim border-t border-cyber-border pt-2">
          {hasImpersonation ? `${impersonationTargets.length} target entity identified` : "Zero impersonation signatures"}
        </div>
      </div>

      {/* 3. Extracted Suspicious URLs */}
      <div className="glass-panel border border-cyber-border-strong p-4 flex flex-col justify-between space-y-3 md:col-span-2 lg:col-span-1 rounded-xs relative group">
        <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t border-l border-cyber-accent/80" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b border-r border-cyber-accent/80" />
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <div className="p-1.5 bg-cyber-bg-secondary border border-cyber-border text-cyber-accent">
              <Link2 className="h-3.5 w-3.5" />
            </div>
            <div>
              <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                Extracted URLs ({urlsFound ? urlsFound.length : 0})
              </h4>
              <p className="text-[10px] text-cyber-text-dim">
                Hyperlinks identified within message body
              </p>
            </div>
          </div>

          <div className="pt-2">
            {hasUrls ? (
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {urlsFound.map((url, idx) => {
                  const hostname = extractHostname(url);
                  return (
                    <div
                      key={idx}
                      className="p-2 bg-cyber-bg-secondary border border-cyber-border flex flex-col gap-1.5"
                    >
                      <span className="font-mono text-[11px] text-cyber-text-secondary truncate" title={url}>
                        {url}
                      </span>
                      <div className="flex items-center justify-end gap-3 pt-1 border-t border-cyber-border/40 text-[10px] font-mono uppercase">
                        <Link
                          href={`/security-tools/url-scanner?query=${encodeURIComponent(url)}`}
                          className="text-cyber-accent hover:underline flex items-center gap-1"
                          title="Inspect target in Website URL Scanner"
                        >
                          <span>Scan URL</span>
                          <ArrowRight className="h-3 w-3" />
                        </Link>
                        {hostname && (
                          <Link
                            href={`/security-tools/ip-domain-analyzer?query=${encodeURIComponent(hostname)}`}
                            className="text-cyber-text-muted hover:text-cyber-accent hover:underline flex items-center gap-1 transition-colors"
                            title={`Inspect ${hostname} in IP & Domain Intelligence Analyzer`}
                          >
                            <span>Domain Intel</span>
                            <ArrowUpRight className="h-3 w-3" />
                          </Link>
                        )}
                      </div>
                    </div>
                  );
                })}

                {hostnames.length > 0 && (
                  <div className="pt-2 border-t border-cyber-border space-y-1.5">
                    <div className="text-[9px] font-mono uppercase tracking-wider text-cyber-text-dim">
                      EXTRACTED DOMAIN ENTITIES
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {hostnames.map((host, idx) => (
                        <Link
                          key={idx}
                          href={`/security-tools/ip-domain-analyzer?query=${encodeURIComponent(host)}`}
                          className="group px-2 py-0.5 bg-cyber-bg-secondary hover:bg-cyber-bg-tertiary border border-cyber-border hover:border-cyber-accent/50 text-[10px] font-mono text-cyber-text-secondary hover:text-cyber-accent inline-flex items-center gap-1 transition-colors"
                          title={`Investigate ${host} in IP & Domain Intelligence Analyzer`}
                        >
                          <span>{host}</span>
                          <ArrowUpRight className="h-2.5 w-2.5 opacity-50 group-hover:opacity-100 transition-opacity" />
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-[11px] font-mono text-cyber-text-dim italic">
                No URLs or hyperlinks identified in message text.
              </div>
            )}
          </div>
        </div>

        <div className="text-[10px] font-mono text-cyber-text-dim border-t border-cyber-border pt-2">
          {hasUrls ? "Hyperlinks extracted via regex parser" : "Zero URLs parsed"}
        </div>
      </div>
    </div>
  );
}

