"use client";

import * as React from "react";
import Link from "next/link";
import { ChevronRight, HardDrive, Shield, Server, Lock } from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { FileAnalyzer } from "@/components/investigation/file-analyzer";

export default function FileAnalyzerPage() {
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
          <span className="text-cyber-accent">FILE BINARY ANALYZER</span>
        </div>

        {/* Page Header */}
        <PageHeader
          editorialTag="INVESTIGATION MODULE // THREAT VECTOR 04"
          title="File Binary Upload & Analysis"
          description="In-memory static binary analysis and magic-byte signature inspection. Detects disguised executable extensions, computes cryptographic signatures, and identifies executable payload anomalies up to 25MB."
          badge={
            <Badge variant="monolithic" radius="xs" className="gap-1.5">
              <Server className="h-3 w-3 text-cyber-accent" />
              FASTAPI CONNECTED
            </Badge>
          }
        />

        {/* Workstation Component */}
        <FileAnalyzer />
      </div>
    </PageContainer>
  );
}
