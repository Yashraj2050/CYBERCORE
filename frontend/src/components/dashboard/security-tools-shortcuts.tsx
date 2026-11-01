"use client";

import * as React from "react";
import Link from "next/link";
import {
  Globe,
  MessageSquare,
  Radio,
  FileSearch,
  Lock,
  ArrowRight,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";

const tools = [
  {
    title: "Website URL Scanner",
    description: "SSRF-protected concurrent threat intelligence, DNS & SSL verification.",
    icon: Globe,
    href: "/security-tools/url-scanner",
    endpoint: "POST /api/v1/scan/",
    tag: "SCANNER",
  },
  {
    title: "Message Phishing Analyzer",
    description: "Urgency tactics, OTP fraud, brand impersonation & heuristic indicators.",
    icon: MessageSquare,
    href: "/security-tools/message-analyzer",
    endpoint: "POST /api/v1/messages/analyze",
    tag: "PATTERNS",
  },
  {
    title: "IP & Domain Intelligence",
    description: "IP routability, reverse DNS PTR, authoritative DNS & RDAP metadata.",
    icon: Radio,
    href: "/security-tools/ip-domain-analyzer",
    endpoint: "POST /api/v1/ip-domain/analyze",
    tag: "NETWORK",
  },
  {
    title: "File Hash Threat Check",
    description: "Check VirusTotal signature database without transmitting file contents.",
    icon: FileSearch,
    href: "/security-tools?tool=files",
    endpoint: "POST /api/v1/files/check-hash",
    tag: "INTEGRITY",
  },
  {
    title: "Password Breach Verifier",
    description: "k-Anonymity privacy check verifying SHA-1 prefix against HIBP records.",
    icon: Lock,
    href: "/security-tools?tool=password",
    endpoint: "GET /api/v1/password/breached/{hash_prefix}",
    tag: "CREDENTIALS",
  },
];

export function SecurityToolsShortcuts() {
  return (
    <div className="glass-panel p-5 rounded-xs space-y-4 relative group border border-cyber-border">
      {/* Corner Monolithic Framing */}
      <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

      <div className="flex items-center justify-between border-b border-cyber-border/60 pb-3">
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-mono text-cyber-accent tracking-widest">{"// ARSENAL"}</span>
          <h2 className="text-xs font-mono font-semibold tracking-tactical uppercase text-cyber-text-primary">
            Fast-Access Investigation Tools
          </h2>
        </div>
        <span className="text-[10px] font-mono text-cyber-text-dim uppercase">
          5 Verified Modules
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {tools.map((t) => {
          const Icon = t.icon;
          return (
            <Link
              key={t.title}
              href={t.href}
              className="p-3.5 bg-cyber-bg border border-cyber-border rounded-xs space-y-2 hover:border-cyber-accent/50 hover:bg-cyber-bg-surface/60 transition-all group/item flex flex-col justify-between"
            >
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex h-7 w-7 items-center justify-center border border-cyber-border bg-cyber-bg-surface rounded-xs group-hover/item:border-cyber-accent/40">
                    <Icon className="h-3.5 w-3.5 text-cyber-accent" />
                  </div>
                  <Badge variant="monolithic" radius="xs">
                    {t.tag}
                  </Badge>
                </div>

                <h3 className="text-xs font-mono font-semibold text-cyber-text-primary group-hover/item:text-cyber-accent transition-colors">
                  {t.title}
                </h3>

                <p className="text-[11px] text-cyber-text-secondary leading-snug font-sans">
                  {t.description}
                </p>
              </div>

              <div className="pt-2 border-t border-cyber-border/40 flex items-center justify-between text-[10px] font-mono text-cyber-text-dim">
                <span className="truncate max-w-[180px]">{t.endpoint}</span>
                <ArrowRight className="h-3 w-3 text-cyber-text-dim group-hover/item:text-cyber-accent group-hover/item:translate-x-0.5 transition-all shrink-0" />
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
