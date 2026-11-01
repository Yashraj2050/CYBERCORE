"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Globe,
  ArrowLeft,
  ShieldAlert,
  ShieldCheck,
  Radar,
  Radio,
  Clock,
  History,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Server,
  Lock,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  UrlScannerForm,
  UrlScanResults,
  ScanErrorState,
} from "@/components/investigation/url-scanner";
import { scannerService } from "@/lib/api/services/scanner";
import type { UrlScanResult, ScanApiError, ScanMode } from "@/types/scanner";

interface RecentScanItem {
  scanId: string;
  url: string;
  domain: string;
  riskScore: number;
  riskCategory: string;
  timestamp: string;
}

function ScannerWorkstation() {
  const searchParams = useSearchParams();
  const idParam = searchParams.get("id") || searchParams.get("scan_id") || "";
  const domainParam = searchParams.get("domain") || "";
  const queryParam = searchParams.get("query") || searchParams.get("url") || "";

  const initialMode: ScanMode = idParam ? "lookup_id" : domainParam ? "lookup_domain" : "scan";
  const initialValue = idParam || domainParam || queryParam;

  const [mode, setMode] = React.useState<ScanMode>(initialMode);
  const [url, setUrl] = React.useState<string>(initialValue);
  const [status, setStatus] = React.useState<"idle" | "scanning" | "success" | "error">("idle");
  const [scanResult, setScanResult] = React.useState<UrlScanResult | null>(null);
  const [scanError, setScanError] = React.useState<ScanApiError | null>(null);
  const [recentScans, setRecentScans] = React.useState<RecentScanItem[]>([]);

  // Track if initial query was executed to avoid double triggers
  const initialTriggerRef = React.useRef(false);

  // Load verified recent scans from sessionStorage on client mount
  React.useEffect(() => {
    try {
      const saved = sessionStorage.getItem("cybercore_recent_scans");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) {
          // Strictly validate that each record has legitimate scan identifiers
          const validRecords = parsed.filter(
            (item): item is RecentScanItem =>
              typeof item === "object" &&
              item !== null &&
              typeof item.scanId === "string" &&
              item.scanId.length > 0 &&
              typeof item.url === "string" &&
              item.url.length > 0
          );
          setRecentScans(validRecords);
        }
      }
    } catch {
      // sessionStorage unavailable or disabled
    }
  }, []);

  const saveToRecent = (result: UrlScanResult) => {
    // Only persist complete records with verified scan_id and url
    if (!result || !result.scan_id || !result.url) return;

    const newItem: RecentScanItem = {
      scanId: result.scan_id,
      url: result.url,
      domain: result.domain || "Unknown Domain",
      riskScore: typeof result.risk_score === "number" ? result.risk_score : 0,
      riskCategory: result.risk_category || "UNKNOWN",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setRecentScans((prev) => {
      const filtered = prev.filter((item) => item.url.toLowerCase() !== newItem.url.toLowerCase());
      const updated = [newItem, ...filtered].slice(0, 5);
      try {
        sessionStorage.setItem("cybercore_recent_scans", JSON.stringify(updated));
      } catch {
        // ignore
      }
      return updated;
    });
  };

  const executeDispatch = React.useCallback(async (target: string, dispatchMode: ScanMode = mode) => {
    const cleanTarget = target.trim();
    if (!cleanTarget) return;

    setStatus("scanning");
    setScanError(null);

    try {
      let result: UrlScanResult;
      if (dispatchMode === "lookup_id") {
        result = await scannerService.getScanById(cleanTarget);
      } else if (dispatchMode === "lookup_domain") {
        result = await scannerService.getScanByDomain(cleanTarget);
      } else {
        result = await scannerService.scanUrl({ url: cleanTarget, source: "web" });
      }

      setScanResult(result);
      setStatus("success");
      saveToRecent(result);
    } catch (err) {
      const classified = scannerService.classifyError(err);
      setScanError(classified);
      setStatus("error");
    }
  }, [mode]);

  // Pre-populate URL query parameter on initial load without automatic execution
  React.useEffect(() => {
    if (initialValue && !initialTriggerRef.current) {
      initialTriggerRef.current = true;
      setUrl(initialValue);
      setMode(initialMode);
      // Explicitly require analyst confirmation; do NOT auto-dispatch
    }
  }, [initialValue, initialMode]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeDispatch(url, mode);
  };

  const handleReset = () => {
    setUrl("");
    setStatus("idle");
    setScanResult(null);
    setScanError(null);
  };

  const handleSelectPreset = (presetUrl: string) => {
    setUrl(presetUrl);
    setMode("scan");
    executeDispatch(presetUrl, "scan");
  };

  const handleInspectRecent = async (item: RecentScanItem) => {
    setStatus("scanning");
    setScanError(null);
    try {
      // First attempt to retrieve from backend in-memory cache by scan_id
      const cached = await scannerService.getScanById(item.scanId);
      setUrl(item.scanId);
      setMode("lookup_id");
      setScanResult(cached);
      setStatus("success");
    } catch {
      // If cached scan expired or backend restarted, re-dispatch fresh scan
      setUrl(item.url);
      setMode("scan");
      executeDispatch(item.url, "scan");
    }
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
          <span className="text-cyber-accent">URL SCANNER</span>
        </div>

        {/* Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-cyber-border pb-6">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="inline-block h-2 w-2 rounded-none bg-cyber-accent" />
              <span className="text-[10px] font-mono uppercase tracking-tactical text-cyber-accent">
                INVESTIGATION MODULE // THREAT VECTOR 01
              </span>
            </div>
            <h1 className="font-mono text-2xl md:text-3xl font-bold tracking-tight text-cyber-text-primary">
              WEBSITE URL SCANNER
            </h1>
            <p className="text-xs md:text-sm font-mono text-cyber-text-secondary max-w-2xl">
              Multi-subsystem inspection engine executing synchronous heuristic scoring, DNS topology
              verification, SSL certificate validation, and threat feed correlation.
            </p>
          </div>

          {/* Engine Status Indicators */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <Badge variant="arctic" className="text-[10px] gap-1.5 py-1">
              <Server className="h-3 w-3" /> FASTAPI /api/v1/scan/
            </Badge>
            <Badge variant="default" className="text-[10px] gap-1.5 py-1">
              <Lock className="h-3 w-3 text-cyber-threat-secure" /> SSRF ENFORCED
            </Badge>
          </div>
        </div>

        {/* Input Workstation */}
        <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 lg:p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-cyber-accent" />
              <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                TARGET SPECIFICATION WORKSTATION
              </h2>
            </div>
            <span className="text-[10px] font-mono text-cyber-text-dim">
              SYNCHRONOUS PIPELINE // ~50-100MS
            </span>
          </div>

          <UrlScannerForm
            url={url}
            onUrlChange={setUrl}
            onSubmit={handleSubmit}
            isLoading={status === "scanning"}
            onReset={handleReset}
            onSelectPreset={handleSelectPreset}
            mode={mode}
            onModeChange={setMode}
          />
        </div>

        {/* Workstation State Renderers */}

        {/* 1. Scanning State */}
        {status === "scanning" && (
          <div className="border border-cyber-border-strong bg-cyber-bg-surface p-12 text-center space-y-6">
            <div className="relative mx-auto w-16 h-16 flex items-center justify-center">
              <div className="absolute inset-0 rounded-full border border-cyber-accent/30 animate-ping opacity-75" />
              <div className="absolute inset-2 rounded-full border border-cyber-accent/60 animate-pulse" />
              <div className="relative p-3 bg-cyber-bg-secondary border border-cyber-accent text-cyber-accent">
                <Radar className="h-7 w-7 animate-spin" />
              </div>
            </div>

            <div className="space-y-2 font-mono">
              <div className="text-[11px] text-cyber-accent uppercase tracking-tactical flex items-center justify-center gap-2">
                <Radio className="h-3 w-3 animate-pulse" />
                <span>ACTIVE INSPECTION IN PROGRESS</span>
              </div>
              <h3 className="text-base font-semibold text-cyber-text-primary">
                Querying FastAPI /api/v1/scan/ Engine
              </h3>
              <p className="text-xs text-cyber-text-dim max-w-md mx-auto break-all">
                Target: <span className="text-cyber-text-secondary">{url}</span>
              </p>
              <div className="text-[10px] text-cyber-text-dim pt-2">
                Evaluating DNS records • Validating SSL chain • Extracting lexical heuristics • Verifying SSRF boundary
              </div>
            </div>
          </div>
        )}

        {/* 2. Error State */}
        {status === "error" && scanError && (
          <ScanErrorState
            error={scanError}
            onRetry={() => executeDispatch(url, mode)}
            onReset={handleReset}
            targetUrl={url}
          />
        )}

        {/* 3. Success State */}
        {status === "success" && scanResult && (
          <UrlScanResults scan={scanResult} />
        )}

        {/* 4. Idle State */}
        {status === "idle" && (
          <div className="space-y-6">
            {/* Capabilities Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="border border-cyber-border bg-cyber-bg-surface p-4 space-y-2">
                <div className="flex items-center gap-2 text-cyber-accent">
                  <ShieldAlert className="h-4 w-4" />
                  <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                    Heuristic Risk Scoring
                  </h4>
                </div>
                <p className="font-mono text-[11px] text-cyber-text-secondary leading-relaxed">
                  Evaluates domain structure, suspicious lexical characteristics, entropy, and known
                  phishing vectors across 6 discrete evaluation subsystems.
                </p>
              </div>

              <div className="border border-cyber-border bg-cyber-bg-surface p-4 space-y-2">
                <div className="flex items-center gap-2 text-cyber-accent">
                  <Server className="h-4 w-4" />
                  <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                    DNS & RDAP Topology
                  </h4>
                </div>
                <p className="font-mono text-[11px] text-cyber-text-secondary leading-relaxed">
                  Inspects A, MX, NS, and TXT records, email spoofing defenses (SPF, DMARC), domain
                  age, registrar integrity, and registration expiration schedules.
                </p>
              </div>

              <div className="border border-cyber-border bg-cyber-bg-surface p-4 space-y-2">
                <div className="flex items-center gap-2 text-cyber-threat-secure">
                  <ShieldCheck className="h-4 w-4" />
                  <h4 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                    RFC 1918 SSRF Defenses
                  </h4>
                </div>
                <p className="font-mono text-[11px] text-cyber-text-secondary leading-relaxed">
                  Hardened against Server-Side Request Forgery. Internal loopback interfaces, private
                  subnets, and reserved address spaces are strictly rejected before dispatch.
                </p>
              </div>
            </div>

            {/* Session Recent Scans */}
            {recentScans.length > 0 && (
              <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-cyber-border pb-3">
                  <div className="flex items-center gap-2">
                    <History className="h-4 w-4 text-cyber-accent" />
                    <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                      SESSION INVESTIGATION LOG
                    </h3>
                  </div>
                  <span className="text-[10px] font-mono text-cyber-text-dim">
                    {recentScans.length} CACHED TARGETS
                  </span>
                </div>

                <div className="divide-y divide-cyber-border font-mono text-xs">
                  {recentScans.map((item) => (
                    <div
                      key={item.scanId}
                      className="py-2.5 flex items-center justify-between gap-4 hover:bg-cyber-bg-secondary px-2 transition-colors"
                    >
                      <div className="flex items-center gap-3 truncate">
                        <Badge
                          variant={
                            item.riskCategory === "CRITICAL"
                              ? "critical"
                              : item.riskCategory === "HIGH"
                              ? "high"
                              : item.riskCategory === "MEDIUM"
                              ? "medium"
                              : "secure"
                          }
                          className="text-[9px]"
                        >
                          {item.riskCategory} ({item.riskScore})
                        </Badge>
                        <span className="text-cyber-text-primary font-medium truncate">
                          {item.url}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        <span className="text-[10px] text-cyber-text-dim">{item.timestamp}</span>
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => handleInspectRecent(item)}
                          className="h-6 px-2 text-[10px] uppercase font-mono"
                        >
                          Inspect
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </PageContainer>
  );
}

export default function UrlScannerPage() {
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
      <ScannerWorkstation />
    </React.Suspense>
  );
}
