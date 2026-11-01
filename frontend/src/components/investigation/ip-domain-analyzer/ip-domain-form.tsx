"use client";

import * as React from "react";
import { Search, Loader2, X, Globe, Radio, Server, ShieldCheck, ArrowRight, CornerDownLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface IpDomainFormProps {
  query: string;
  onChange: (value: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  onClear: () => void;
  onSelectPreset: (preset: string) => void;
  isLoading: boolean;
}

const PRESET_EXAMPLES = [
  { label: "Google DNS", value: "8.8.8.8", type: "IPv4" },
  { label: "Cloudflare DNS", value: "1.1.1.1", type: "IPv4" },
  { label: "Google IPv6", value: "2001:4860:4860::8888", type: "IPv6" },
  { label: "Apex Domain", value: "google.com", type: "Domain" },
  { label: "Subdomain", value: "api.github.com", type: "Subdomain" },
];

export function IpDomainForm({
  query,
  onChange,
  onSubmit,
  onClear,
  onSelectPreset,
  isLoading,
}: IpDomainFormProps) {
  const trimmed = query.trim();

  // Detect input classification
  const inputType = React.useMemo(() => {
    if (!trimmed) return null;
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(trimmed)) return "IPv4";
    if (trimmed.includes(":") && !trimmed.startsWith("http")) return "IPv6";
    if (trimmed.includes("/")) return "URL (will strip)";
    if (trimmed.split(".").length > 2) return "Subdomain";
    if (trimmed.includes(".")) return "Domain";
    return "Hostname";
  }, [trimmed]);

  const isValidLength = trimmed.length >= 2 && trimmed.length <= 253;

  return (
    <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 lg:p-6 space-y-4">
      {/* Form Workspace */}
      <form onSubmit={onSubmit} className="space-y-4">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-cyber-text-dim">
            <label htmlFor="target-input" className="uppercase tracking-wider font-semibold flex items-center gap-1.5 text-cyber-text-primary">
              <Radio className="h-3.5 w-3.5 text-cyber-accent" />
              <span>TARGET ENTITY IDENTIFIER</span>
            </label>

            <div className="flex items-center gap-3">
              {inputType && (
                <Badge variant="outline" className="text-[10px] font-mono text-cyber-accent">
                  DETECTED: {inputType}
                </Badge>
              )}
              <span className="text-[11px]">
                {trimmed.length} / 253 CHARS
              </span>
            </div>
          </div>

          {/* Main Search Input Group */}
          <div className="relative flex items-center">
            <div className="absolute left-3.5 pointer-events-none text-cyber-text-dim">
              <Search className="h-4 w-4" />
            </div>

            <input
              id="target-input"
              type="text"
              value={query}
              onChange={(e) => onChange(e.target.value)}
              placeholder="Enter IPv4, IPv6, domain (e.g. google.com), or subdomain (e.g. api.github.com)..."
              disabled={isLoading}
              className="w-full bg-cyber-bg border border-cyber-border pl-10 pr-24 py-3 font-mono text-sm text-cyber-text-primary placeholder:text-cyber-text-muted focus:outline-none focus:border-cyber-accent transition-colors rounded-none disabled:opacity-50"
              autoComplete="off"
              spellCheck="false"
            />

            <div className="absolute right-2.5 flex items-center gap-1.5">
              {query && !isLoading && (
                <button
                  type="button"
                  onClick={onClear}
                  className="p-1 text-cyber-text-dim hover:text-cyber-text-primary transition-colors"
                  title="Clear input"
                >
                  <X className="h-4 w-4" />
                </button>
              )}

              <Button
                type="submit"
                disabled={isLoading || !trimmed || !isValidLength}
                className="h-8 px-3 font-mono text-xs uppercase tracking-wider gap-1.5 rounded-none"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-3 w-3 animate-spin" />
                    <span>ANALYZING</span>
                  </>
                ) : (
                  <>
                    <span>INSPECT</span>
                    <CornerDownLeft className="h-3 w-3" />
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>

        {/* Validation Warning */}
        {query.length > 0 && !isValidLength && (
          <div className="text-[11px] font-mono text-cyber-threat-high">
            Query must be between 2 and 253 characters in length.
          </div>
        )}

        {/* Operational Guidance & Presets */}
        <div className="pt-2 border-t border-cyber-border flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-cyber-text-dim">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase text-cyber-text-dim tracking-wider font-semibold">
              SAMPLE TARGETS:
            </span>
            {PRESET_EXAMPLES.map((preset) => (
              <button
                key={preset.value}
                type="button"
                onClick={() => onSelectPreset(preset.value)}
                disabled={isLoading}
                className="px-2 py-0.5 bg-cyber-bg-secondary hover:bg-cyber-bg-tertiary border border-cyber-border text-cyber-text-secondary hover:text-cyber-text-primary text-[11px] font-mono transition-colors rounded-none disabled:opacity-50"
              >
                {preset.value}
              </button>
            ))}
          </div>

          <div className="text-[10px] text-cyber-text-dim">
            Deterministic DNS topology & RFC 7489 registration verification
          </div>
        </div>
      </form>

      {/* Restrained Loading Banner */}
      {isLoading && (
        <div className="p-4 bg-cyber-bg-secondary border border-cyber-border flex items-center justify-between gap-4 font-mono text-xs">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Loader2 className="h-4 w-4 animate-spin text-cyber-accent" />
            </div>
            <div>
              <div className="text-cyber-text-primary font-semibold text-[11px] uppercase tracking-wider">
                QUERYING TECHNICAL TOPOLOGY
              </div>
              <div className="text-cyber-text-dim text-[10px]">
                Resolving authoritative DNS records (A, MX, NS, TXT), checking DMARC policy, and contacting RDAP registries.
              </div>
            </div>
          </div>

          <Badge variant="outline" className="text-[10px] animate-pulse">
            NETWORK DISPATCH ACTIVE
          </Badge>
        </div>
      )}
    </div>
  );
}

