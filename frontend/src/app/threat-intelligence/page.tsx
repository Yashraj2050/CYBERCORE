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
  Send,
  Info,
  Radio,
  Check,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { dashboardService } from "@/lib/api/services/dashboard";
import type { ThreatFeedCampaign, ThreatReportPayload, ThreatReportResponse, CommunityReportItem } from "@/types/dashboard";

export default function ThreatIntelligencePage() {
  const [campaigns, setCampaigns] = React.useState<ThreatFeedCampaign[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  // Community Reports State
  const [reports, setReports] = React.useState<CommunityReportItem[]>([]);
  const [totalReportCount, setTotalReportCount] = React.useState<number>(0);
  const [loadingReports, setLoadingReports] = React.useState<boolean>(true);
  const [reportsError, setReportsError] = React.useState<string | null>(null);

  // Reporting State
  const [reportUrl, setReportUrl] = React.useState("");
  const [reportType, setReportType] = React.useState<string>("phishing");
  const [reportDesc, setReportDesc] = React.useState("");
  const [reporting, setReporting] = React.useState(false);
  const [reportResult, setReportResult] = React.useState<ThreatReportResponse | null>(null);
  const [reportError, setReportError] = React.useState<string | null>(null);

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

  const loadReports = React.useCallback(async () => {
    setLoadingReports(true);
    setReportsError(null);
    try {
      const data = await dashboardService.getCommunityReports(15);
      setReports(data.reports || []);
      setTotalReportCount(data.total_count ?? (data.reports ? data.reports.length : 0));
    } catch (err) {
      setReportsError(
        err instanceof Error ? err.message : "Failed to load community threat reports"
      );
    } finally {
      setLoadingReports(false);
    }
  }, []);

  React.useEffect(() => {
    loadFeed();
    loadReports();
  }, [loadFeed, loadReports]);

  const handleReportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanUrl = reportUrl.trim();
    if (!cleanUrl) return;

    setReporting(true);
    setReportError(null);
    setReportResult(null);

    try {
      const res = await dashboardService.reportThreat({
        url: cleanUrl,
        threat_type: reportType,
        description: reportDesc.trim() || undefined,
      });
      setReportResult(res);
      setReportUrl("");
      setReportDesc("");
      // Reload reports to display the newly persisted report
      loadReports();
    } catch (err) {
      setReportError(err instanceof Error ? err.message : "Failed to submit threat report");
    } finally {
      setReporting(false);
    }
  };

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

      {/* Intelligence Provenance & Scope Disclaimer */}
      <div className="p-4 bg-cyber-bg-surface border border-cyber-border rounded-xs flex items-start gap-3 font-mono text-xs text-cyber-text-secondary">
        <Info className="h-4 w-4 text-cyber-accent shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-semibold text-cyber-text-primary uppercase tracking-wider text-[11px] block">
            INTELLIGENCE PROVENANCE & FEED ATTRIBUTION
          </span>
          <p className="text-cyber-text-dim leading-relaxed text-[11px]">
            The threat campaigns cataloged below represent human-curated reference advisories served by the FastAPI engine
            (<code className="text-cyber-accent">GET /api/v1/dashboard/threat-feed</code>). They serve as verified threat patterns
            for SMS smishing, cryptocurrency drainers, and courier fee fraud. This instance does not stream uncurated commercial threat feeds.
          </p>
        </div>
      </div>

      {/* Campaigns Matrix */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-2">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-cyber-accent" />
            <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              ACTIVE THREAT CAMPAIGNS ({campaigns.length})
            </h2>
          </div>
          <span className="text-[10px] font-mono text-cyber-text-dim">
            FASTAPI /dashboard/threat-feed
          </span>
        </div>

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
                    <span className="text-emerald-400">CURATED REF</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Community Threat Reporting Section */}
      <div className="glass-panel p-6 border border-cyber-border rounded-xs space-y-5 relative">
        <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyber-accent" />

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-border pb-3">
          <div className="space-y-0.5">
            <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-cyber-text-primary flex items-center gap-2">
              <Shield className="h-4 w-4 text-cyber-accent" />
              SUBMIT THREAT TO COMMUNITY DEFENSE BUS
            </h3>
            <p className="text-xs font-mono text-cyber-text-dim">
              Submit malicious URLs, phishing pages, or suspicious domains for security team review.
            </p>
          </div>
          <Badge variant="arctic" className="text-[10px]">
            POST /api/v1/dashboard/report
          </Badge>
        </div>

        <form onSubmit={handleReportSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2 space-y-1">
              <label htmlFor="report-url" className="text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider block">
                Target URL or Domain *
              </label>
              <input
                id="report-url"
                type="text"
                value={reportUrl}
                onChange={(e) => setReportUrl(e.target.value)}
                placeholder="e.g. https://phish-secure-portal.com/login"
                required
                disabled={reporting}
                className="w-full bg-cyber-bg border border-cyber-border px-3 py-2 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none focus:border-cyber-accent transition-colors rounded-none"
              />
            </div>

            <div className="space-y-1">
              <label htmlFor="report-type" className="text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider block">
                Threat Classification
              </label>
              <select
                id="report-type"
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                disabled={reporting}
                className="w-full bg-cyber-bg border border-cyber-border px-3 py-2 text-xs font-mono text-cyber-text-primary focus:outline-none focus:border-cyber-accent transition-colors rounded-none"
              >
                <option value="phishing">Phishing / Fake Login</option>
                <option value="malware">Malware / Dropper</option>
                <option value="scam">Scam / Financial Fraud</option>
                <option value="impersonation">Brand Impersonation</option>
                <option value="other">Other Suspicious Target</option>
              </select>
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor="report-desc" className="text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider block">
              Observed Indicators or Context (Optional)
            </label>
            <textarea
              id="report-desc"
              value={reportDesc}
              onChange={(e) => setReportDesc(e.target.value)}
              placeholder="e.g. Received via SMS claiming urgent account suspension. Asks for OTP."
              rows={2}
              maxLength={1000}
              disabled={reporting}
              className="w-full bg-cyber-bg border border-cyber-border px-3 py-2 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none focus:border-cyber-accent transition-colors rounded-none resize-none"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <Button
              type="submit"
              disabled={reporting || !reportUrl.trim()}
              className="h-9 px-5 text-xs font-mono gap-2"
            >
              <Send className="h-3.5 w-3.5" />
              <span>{reporting ? "TRANSMITTING..." : "SUBMIT REPORT"}</span>
            </Button>

            <span className="text-[10px] font-mono text-cyber-text-dim">
              QUEUED TO COMMUNITY TRIAGE PIPELINE
            </span>
          </div>
        </form>

        {/* Submission Feedback / Confirmation */}
        {reportResult && (
          <div
            className={`p-4 rounded-xs space-y-1.5 font-mono text-xs border ${
              reportResult.status === "DUPLICATE_ACKNOWLEDGED"
                ? "bg-cyber-threat-high-bg border-cyber-threat-high-border text-cyber-threat-high"
                : "bg-cyber-threat-secure-bg border-cyber-threat-secure-border text-cyber-threat-secure"
            }`}
          >
            <div className="flex items-center gap-2 font-semibold">
              {reportResult.status === "DUPLICATE_ACKNOWLEDGED" ? (
                <AlertTriangle className="h-4 w-4 shrink-0" />
              ) : (
                <Check className="h-4 w-4 shrink-0" />
              )}
              <span>{reportResult.message}</span>
            </div>
            <div className="text-[11px] opacity-90 pl-6 space-y-0.5">
              <div>REPORT ID: <code>{reportResult.report.id}</code></div>
              <div>
                REVIEW STATUS:{" "}
                <span className="font-semibold px-1 py-0.5 rounded-xs bg-black/30 border border-current">
                  {reportResult.report.status === "PENDING_REVIEW"
                    ? "PENDING REVIEW"
                    : reportResult.report.status}
                </span>
              </div>
              <div>TIMESTAMP: <code>{reportResult.report.reported_at}</code></div>
              {reportResult.report.risk_classification && (
                <div>CLASSIFICATION: <code>{reportResult.report.risk_classification}</code></div>
              )}
            </div>
          </div>
        )}

        {/* Error Feedback */}
        {reportError && (
          <div className="p-3 bg-cyber-threat-critical-bg border border-cyber-threat-critical-border text-cyber-threat-critical rounded-xs font-mono text-xs flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span>SUBMISSION FAILED: {reportError}</span>
          </div>
        )}
      </div>

      {/* Community Threat Reports Feed */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-border pb-2">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-cyber-accent" />
            <h2 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              VERIFIED COMMUNITY THREAT REPORTS ({totalReportCount})
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono text-cyber-text-dim hidden sm:inline">
              GET /api/v1/dashboard/reports
            </span>
            <Button
              variant="monolithic"
              size="xs"
              onClick={loadReports}
              disabled={loadingReports}
              className="gap-1 text-[10px] font-mono"
            >
              <RefreshCw
                className={`h-2.5 w-2.5 ${loadingReports ? "animate-spin text-cyber-accent" : "text-cyber-text-dim"}`}
              />
              <span>REFRESH</span>
            </Button>
          </div>
        </div>

        {loadingReports ? (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-16 bg-cyber-bg-secondary border border-cyber-border rounded-xs animate-pulse"
              />
            ))}
          </div>
        ) : reportsError ? (
          <div className="p-6 border border-cyber-threat-critical-border bg-cyber-threat-critical-bg rounded-xs text-center space-y-2 text-xs font-mono">
            <p className="text-cyber-threat-critical">
              COMMUNITY REPORTS OFFLINE: {reportsError}
            </p>
            <Button size="xs" variant="outline" onClick={loadReports}>
              Retry Connection
            </Button>
          </div>
        ) : reports.length === 0 ? (
          <div className="p-8 border border-cyber-border bg-cyber-bg-secondary rounded-xs text-center text-xs font-mono text-cyber-text-dim">
            No community reports recorded in the database yet. Submit the first threat indicator above.
          </div>
        ) : (
          <div className="border border-cyber-border rounded-xs divide-y divide-cyber-border bg-cyber-bg-secondary overflow-hidden">
            {reports.map((rep) => {
              const isPending = rep.status === "PENDING_REVIEW";
              const isVerified = rep.status === "VERIFIED";
              const isRejected = rep.status === "REJECTED";

              return (
                <div
                  key={rep.id}
                  className="p-3.5 sm:p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-cyber-bg-surface/50 transition-colors font-mono text-xs"
                >
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-cyber-text-primary break-all">
                        {rep.url}
                      </span>
                      <span className="text-[10px] uppercase px-1.5 py-0.5 border border-cyber-border bg-cyber-bg text-cyber-accent">
                        {rep.threat_type}
                      </span>
                    </div>
                    {rep.description && (
                      <p className="text-[11px] text-cyber-text-secondary truncate max-w-xl">
                        {rep.description}
                      </p>
                    )}
                    <div className="text-[10px] text-cyber-text-dim flex items-center gap-3">
                      <span>ID: {rep.id}</span>
                      <span>•</span>
                      <span>
                        {new Date(rep.reported_at).toLocaleDateString([], {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })}{" "}
                        {new Date(rep.reported_at).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 self-start sm:self-center">
                    {rep.risk_classification && (
                      <Badge
                        variant={
                          rep.risk_classification === "CRITICAL"
                            ? "critical"
                            : rep.risk_classification === "HIGH"
                            ? "high"
                            : rep.risk_classification === "SUSPICIOUS"
                            ? "medium"
                            : rep.risk_classification === "SAFE"
                            ? "secure"
                            : "monolithic"
                        }
                        radius="xs"
                        className="text-[10px]"
                      >
                        {rep.risk_classification}
                      </Badge>
                    )}
                    <Badge
                      variant={
                        isVerified
                          ? "critical"
                          : isPending
                          ? "medium"
                          : isRejected
                          ? "monolithic"
                          : "default"
                      }
                      radius="xs"
                      dot
                      className="text-[10px]"
                    >
                      {rep.status}
                    </Badge>
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
