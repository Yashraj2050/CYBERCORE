"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Radio,
  ChevronRight,
  Globe,
  Server,
  Lock,
  Radar,
  FileCode,
  Shield,
  AlertCircle,
  HelpCircle,
  Mail,
  Building,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { Badge } from "@/components/ui/badge";
import {
  IpDomainForm,
  IpDomainResults,
  IpDomainError,
} from "@/components/investigation/ip-domain-analyzer";
import { ipDomainService } from "@/lib/api/services/ip-domain";
import type { IpDomainResult, IpDomainApiError } from "@/types/ip-domain";

function IpDomainWorkstation() {
  const searchParams = useSearchParams();
  const queryParam = searchParams.get("query") || searchParams.get("target") || "";

  const [query, setQuery] = React.useState<string>(queryParam);
  const [status, setStatus] = React.useState<"idle" | "analyzing" | "success" | "error">("idle");
  const [result, setResult] = React.useState<IpDomainResult | null>(null);
  const [error, setError] = React.useState<IpDomainApiError | null>(null);

  // Pre-populate query if passed via URL parameter, but DO NOT auto-execute (strict analyst confirmation)
  React.useEffect(() => {
    if (queryParam) {
      setQuery(queryParam);
    }
  }, [queryParam]);

  const executeAnalysis = React.useCallback(async (target: string) => {
    const cleanTarget = target.trim();
    if (!cleanTarget) return;

    setStatus("analyzing");
    setError(null);

    try {
      const data = await ipDomainService.analyze({ query: cleanTarget });
      setResult(data);
      setStatus("success");
    } catch (err) {
      const classified = ipDomainService.classifyError(err);
      setError(classified);
      setStatus("error");
    }
  }, []);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeAnalysis(query);
  };

  const handleReset = () => {
    setQuery("");
    setStatus("idle");
    setResult(null);
    setError(null);
  };

  const handleSelectPreset = (presetText: string) => {
    setQuery(presetText);
    executeAnalysis(presetText);
  };

  return (
    <PageContainer>
      <div className="space-y-6">
        {/* Breadcrumbs */}
        <div className="flex items-center gap-2 text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider">
          <Link href="/" className="hover:text-cyber-accent transition-colors">
            CYBERCORE
          </Link>
          <ChevronRight className="h-3 w-3 text-cyber-border-strong" />
          <Link href="/security-tools" className="hover:text-cyber-accent transition-colors">
            SECURITY TOOLS
          </Link>
          <ChevronRight className="h-3 w-3 text-cyber-border-strong" />
          <span className="text-cyber-accent">IP & DOMAIN INTELLIGENCE</span>
        </div>

        {/* Editorial Workstation Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-cyber-border pb-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-none bg-cyber-accent" />
              <span className="text-[10px] font-mono uppercase tracking-widest text-cyber-text-dim">
                MODULE 03 // TECHNICAL NETWORK RECONNAISSANCE
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-mono font-bold tracking-tight text-cyber-text-primary">
              IP & DOMAIN INTELLIGENCE ANALYZER
            </h1>
            <p className="text-xs sm:text-sm font-mono text-cyber-text-secondary max-w-3xl leading-relaxed">
              Authoritative DNS topology, reverse PTR host routing, RFC 7489 email authentication policy,
              and structured RDAP registration metadata inspection.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline" className="text-[10px] font-mono text-cyber-accent">
              RFC 7489 DMARC
            </Badge>
            <Badge variant="outline" className="text-[10px] font-mono text-cyber-accent">
              SSRF PROTECTED
            </Badge>
            <Badge variant="outline" className="text-[10px] font-mono text-cyber-accent">
              DETERMINISTIC
            </Badge>
          </div>
        </div>

        {/* Investigation Form Input */}
        <IpDomainForm
          query={query}
          onChange={setQuery}
          onSubmit={handleSubmit}
          onClear={handleReset}
          onSelectPreset={handleSelectPreset}
          isLoading={status === "analyzing"}
        />

        {/* Dynamic Investigation Result Area */}
        {status === "error" && error && (
          <IpDomainError error={error} onRetry={() => executeAnalysis(query)} onClear={handleReset} />
        )}

        {status === "success" && result && (
          <IpDomainResults result={result} />
        )}

        {/* Initial Workstation Context (Idle State) */}
        {status === "idle" && (
          <div className="space-y-6 pt-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-5 bg-cyber-bg-surface border border-cyber-border space-y-2 font-mono">
                <div className="flex items-center gap-2 text-cyber-accent text-xs font-semibold uppercase">
                  <Radio className="h-4 w-4" />
                  <span>IP ROUTING & PTR</span>
                </div>
                <p className="text-xs text-cyber-text-secondary leading-relaxed">
                  Verifies public/private classification, RFC1918 boundaries, and reverse DNS PTR hostname resolution
                  for both IPv4 and IPv6 addresses.
                </p>
              </div>

              <div className="p-5 bg-cyber-bg-surface border border-cyber-border space-y-2 font-mono">
                <div className="flex items-center gap-2 text-cyber-accent text-xs font-semibold uppercase">
                  <Server className="h-4 w-4" />
                  <span>DNS TOPOLOGY & DMARC</span>
                </div>
                <p className="text-xs text-cyber-text-secondary leading-relaxed">
                  Queries authoritative A, MX, NS, and TXT records concurrently. Implements RFC 7489 DMARC resolution
                  with organizational fallback for subdomains.
                </p>
              </div>

              <div className="p-5 bg-cyber-bg-surface border border-cyber-border space-y-2 font-mono">
                <div className="flex items-center gap-2 text-cyber-accent text-xs font-semibold uppercase">
                  <Building className="h-4 w-4" />
                  <span>STRUCTURED RDAP REGISTRY</span>
                </div>
                <p className="text-xs text-cyber-text-secondary leading-relaxed">
                  Fetches structured registration timestamps, domain age, registry status codes, and registrar metadata
                  via modern RDAP protocols.
                </p>
              </div>
            </div>

            {/* Principles & Honesty Notice */}
            <div className="p-4 bg-cyber-bg-secondary border border-cyber-border space-y-2 font-mono text-xs">
              <div className="flex items-center gap-2 text-cyber-accent font-semibold text-[10px] uppercase tracking-wider">
                <AlertCircle className="h-3.5 w-3.5" />
                <span>TECHNICAL TRANSPARENCY & ENGINE BOUNDARIES</span>
              </div>
              <p className="text-[11px] text-cyber-text-secondary leading-relaxed">
                CYBERCORE utilizes transparent, deterministic network queries. This module evaluates DNS technical configuration
                and RDAP registration age. It does not integrate external blacklists, GeoIP databases, or ASN data. Technical
                signals like missing PTR or new domain age are displayed as objective observations and do not independently
                establish malicious intent.
              </p>
            </div>
          </div>
        )}
      </div>
    </PageContainer>
  );
}

export default function IpDomainAnalyzerPage() {
  return (
    <React.Suspense
      fallback={
        <PageContainer>
          <div className="p-12 text-center font-mono text-xs text-cyber-text-dim">
            Loading investigation module...
          </div>
        </PageContainer>
      }
    >
      <IpDomainWorkstation />
    </React.Suspense>
  );
}

