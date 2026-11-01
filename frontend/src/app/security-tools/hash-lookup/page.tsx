"use client";

import * as React from "react";
import Link from "next/link";
import { ChevronRight, Hash, Shield, Server, Lock } from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { HashChecker } from "@/components/investigation/hash-checker";

export default function HashLookupPage() {
  return (
    <PageContainer>
      <div className="space-y-6">
        {/* Monolithic Breadcrumbs */}
        <div className="flex items-center gap-2 text-[10px] font-mono text-cyber-text-dim uppercase tracking-wider">
          <Link href="/" className="hover:text-cyber-accent transition-colors">
            CYBERCORE
          </Link>
          <ChevronRight className="h-3 w-3 text-cyber-border-strong" />
          <Link href="/security-tools" className="hover:text-cyber-accent transition-colors">
            SECURITY TOOLS
          </Link>
          <ChevronRight className="h-3 w-3 text-cyber-border-strong" />
          <span className="text-cyber-accent">CRYPTOGRAPHIC HASH LOOKUP</span>
        </div>

        {/* Page Header */}
        <PageHeader
          editorialTag="INVESTIGATION MODULE // THREAT VECTOR 05"
          title="Cryptographic Hash Lookup"
          description="Privacy-preserving cryptographic hash reputation and heuristic analysis. Inspects MD5, SHA-1, and SHA-256 digests against known threat databases without transmitting file contents."
          badge={
            <Badge variant="monolithic" radius="xs" className="gap-1.5">
              <Server className="h-3 w-3 text-cyber-accent" />
              FASTAPI CONNECTED
            </Badge>
          }
        />

        {/* Workstation Component */}
        <HashChecker />
      </div>
    </PageContainer>
  );
}
