"use client";

import * as React from "react";
import Link from "next/link";
import {
  Server,
  Network,
  FileText,
  Mail,
  ShieldCheck,
  ShieldAlert,
  Calendar,
  AlertCircle,
  CheckCircle2,
  ListChecks,
  Info,
  ArrowUpRight,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { DnsDetails, WhoisDetails } from "@/types/scanner";

interface ScanTechnicalFindingsProps {
  dns: DnsDetails;
  whois: WhoisDetails;
  recommendedActions: string[];
  domain?: string;
}

export function ScanTechnicalFindings({
  dns,
  whois,
  recommendedActions,
  domain,
}: ScanTechnicalFindingsProps) {
  const hasTxtData = Array.isArray(dns.txt_records) && dns.txt_records.length > 0;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Column 1: DNS Topology & Records */}
      <div className="lg:col-span-6 border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-cyber-border pb-3">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-cyber-accent" />
            <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
              DNS INFRASTRUCTURE & AUTHENTICATION
            </h3>
          </div>
          <span className="text-[10px] font-mono text-cyber-text-dim">RESOLVER TELEMETRY</span>
        </div>

        {/* Email Security & Record Flags */}
        <div className="grid grid-cols-3 gap-2">
          <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-border text-center space-y-1">
            <div className="text-[10px] font-mono uppercase text-cyber-text-dim">SPF RECORD</div>
            <div className="flex items-center justify-center">
              {hasTxtData ? (
                dns.has_spf ? (
                  <Badge variant="secure" className="text-[9px]">PRESENT</Badge>
                ) : (
                  <Badge variant="outline" className="text-[9px]">NOT IN TXT</Badge>
                )
              ) : (
                <Badge variant="outline" className="text-[9px]">NO TXT DATA</Badge>
              )}
            </div>
          </div>

          <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-border text-center space-y-1">
            <div className="text-[10px] font-mono uppercase text-cyber-text-dim">DMARC POLICY</div>
            <div className="flex items-center justify-center">
              {hasTxtData ? (
                dns.has_dmarc ? (
                  <Badge variant="secure" className="text-[9px]">ACTIVE</Badge>
                ) : (
                  <Badge variant="outline" className="text-[9px]">NOT IN TXT</Badge>
                )
              ) : (
                <Badge variant="outline" className="text-[9px]">NO TXT DATA</Badge>
              )}
            </div>
          </div>

          <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-border text-center space-y-1">
            <div className="text-[10px] font-mono uppercase text-cyber-text-dim">DKIM SIGNATURE</div>
            <div className="flex items-center justify-center">
              {hasTxtData ? (
                dns.has_dkim_hint ? (
                  <Badge variant="arctic" className="text-[9px]">HINT DETECTED</Badge>
                ) : (
                  <Badge variant="outline" className="text-[9px]">NOT IN TXT</Badge>
                )
              ) : (
                <Badge variant="outline" className="text-[9px]">NO TXT DATA</Badge>
              )}
            </div>
          </div>
        </div>

        {/* DNS Error notification if resolver failed */}
        {dns.error && (
          <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-threat-high/40 text-cyber-threat-high text-xs font-mono flex items-start gap-2">
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <span>Resolver note: {dns.error}</span>
          </div>
        )}

        {/* Records Breakdown */}
        <div className="space-y-3 pt-1 font-mono text-xs">
          {/* A Records */}
          <div className="space-y-1">
            <div className="text-[10px] uppercase text-cyber-text-dim tracking-wider flex items-center justify-between">
              <span>ADDRESS (A) RECORDS</span>
              <span>{dns.a_records?.length || 0} IPs</span>
            </div>
            {dns.a_records && dns.a_records.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {dns.a_records.map((ip, i) => (
                  <Link
                    key={i}
                    href={`/security-tools/ip-domain-analyzer?query=${encodeURIComponent(ip)}`}
                    className="group px-2 py-0.5 bg-cyber-bg-secondary hover:bg-cyber-bg-tertiary border border-cyber-border hover:border-cyber-accent/50 text-cyber-text-secondary hover:text-cyber-accent text-[11px] inline-flex items-center gap-1 transition-colors"
                    title={`Investigate IP ${ip} in IP & Domain Intelligence Analyzer`}
                  >
                    <span>{ip}</span>
                    <ArrowUpRight className="h-2.5 w-2.5 opacity-50 group-hover:opacity-100 transition-opacity" />
                  </Link>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-cyber-text-dim italic">No A records resolved.</div>
            )}
          </div>

          {/* MX Records */}
          <div className="space-y-1">
            <div className="text-[10px] uppercase text-cyber-text-dim tracking-wider flex items-center justify-between">
              <span>MAIL EXCHANGER (MX)</span>
              <span>{dns.mx_records?.length || 0} hosts</span>
            </div>
            {dns.mx_records && dns.mx_records.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {dns.mx_records.map((mx, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 bg-cyber-bg-secondary border border-cyber-border text-cyber-text-secondary text-[11px] break-all"
                  >
                    {mx}
                  </span>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-cyber-text-dim italic">No MX records configured.</div>
            )}
          </div>

          {/* NS Records */}
          <div className="space-y-1">
            <div className="text-[10px] uppercase text-cyber-text-dim tracking-wider flex items-center justify-between">
              <span>NAMESERVERS (NS)</span>
              <span>{dns.ns_records?.length || 0} servers</span>
            </div>
            {dns.ns_records && dns.ns_records.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {dns.ns_records.map((ns, i) => (
                  <span
                    key={i}
                    className="px-2 py-0.5 bg-cyber-bg-secondary border border-cyber-border text-cyber-text-secondary text-[11px] break-all"
                  >
                    {ns}
                  </span>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-cyber-text-dim italic">No NS records returned.</div>
            )}
          </div>

          {/* TXT Records */}
          {dns.txt_records && dns.txt_records.length > 0 && (
            <div className="space-y-1">
              <div className="text-[10px] uppercase text-cyber-text-dim tracking-wider">
                TEXT (TXT) RECORDS ({dns.txt_records.length})
              </div>
              <div className="max-h-24 overflow-y-auto space-y-1 pr-1">
                {dns.txt_records.map((txt, i) => (
                  <div
                    key={i}
                    className="p-1.5 bg-cyber-bg-secondary border border-cyber-border text-[10px] text-cyber-text-secondary truncate"
                    title={txt}
                  >
                    {txt}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Column 2: WHOIS / RDAP & Recommended Actions */}
      <div className="lg:col-span-6 space-y-6">
        {/* RDAP / WHOIS Registry Metadata */}
        <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <div className="flex items-center gap-2">
              <Network className="h-4 w-4 text-cyber-accent" />
              <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                WHOIS & REGISTRATION METRICS
              </h3>
            </div>
            {domain ? (
              <Link
                href={`/security-tools/ip-domain-analyzer?query=${encodeURIComponent(domain)}`}
                className="text-[10px] font-mono text-cyber-accent hover:underline flex items-center gap-1"
                title={`Investigate ${domain} in IP & Domain Intelligence Analyzer`}
              >
                <span>DOMAIN INTEL</span>
                <ArrowUpRight className="h-2.5 w-2.5" />
              </Link>
            ) : (
              <span className="text-[10px] font-mono text-cyber-text-dim">REGISTRY DATA</span>
            )}
          </div>

          <div className="space-y-3 font-mono text-xs">
            <div className="grid grid-cols-2 gap-3">
              <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] uppercase text-cyber-text-dim">REGISTRAR</div>
                <div className="text-cyber-text-primary truncate font-medium" title={whois.registrar || "Unknown"}>
                  {whois.registrar || "Not Available"}
                </div>
              </div>

              <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] uppercase text-cyber-text-dim">DOMAIN AGE</div>
                <div className="text-cyber-text-primary font-medium">
                  {typeof whois.domain_age_days === "number" ? (
                    <span className="flex items-baseline gap-1">
                      <span>{whois.domain_age_days.toLocaleString()}</span>
                      <span className="text-[10px] text-cyber-text-dim">days</span>
                    </span>
                  ) : (
                    <span className="text-cyber-text-dim">Unspecified</span>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] uppercase text-cyber-text-dim">REGISTRATION DATE</div>
                <div className="text-cyber-text-secondary text-[11px] truncate">
                  {whois.registration_date ? whois.registration_date.split("T")[0] : "Not Available"}
                </div>
              </div>

              <div className="p-2.5 bg-cyber-bg-secondary border border-cyber-border space-y-1">
                <div className="text-[10px] uppercase text-cyber-text-dim">EXPIRATION DATE</div>
                <div className="text-cyber-text-secondary text-[11px] truncate">
                  {whois.expiration_date ? whois.expiration_date.split("T")[0] : "Not Available"}
                </div>
              </div>
            </div>

            {/* WHOIS Status Flags */}
            {whois.status && whois.status.length > 0 && (
              <div className="space-y-1 pt-1">
                <div className="text-[10px] uppercase text-cyber-text-dim tracking-wider">REGISTRATION STATUS</div>
                <div className="flex flex-wrap gap-1">
                  {whois.status.map((st, i) => (
                    <span
                      key={i}
                      className="px-1.5 py-0.5 bg-cyber-bg-secondary border border-cyber-border text-[9px] text-cyber-text-muted"
                    >
                      {st}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* WHOIS Error notice if registry unavailable */}
            {whois.error && (
              <div className="p-2 bg-cyber-bg-secondary border border-cyber-border text-cyber-text-dim text-[11px]">
                Registry notice: {whois.error}
              </div>
            )}
          </div>
        </div>

        {/* Recommended Actions */}
        <div className="border border-cyber-border-strong bg-cyber-bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-cyber-border pb-3">
            <div className="flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-cyber-accent" />
              <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-cyber-text-primary">
                RECOMMENDED OPERATIONAL ACTIONS
              </h3>
            </div>
            <span className="text-[10px] font-mono text-cyber-text-dim">SOC PROTOCOL</span>
          </div>

          {recommendedActions && recommendedActions.length > 0 ? (
            <ul className="space-y-2 font-mono text-xs">
              {recommendedActions.map((action, idx) => (
                <li
                  key={idx}
                  className="flex items-start gap-2.5 p-2 bg-cyber-bg-secondary border border-cyber-border text-cyber-text-secondary"
                >
                  <CheckCircle2 className="h-3.5 w-3.5 text-cyber-accent shrink-0 mt-0.5" />
                  <span className="leading-relaxed text-[11px]">{action}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="text-xs font-mono text-cyber-text-dim italic">
              No immediate countermeasures or quarantine actions required for this object.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

