"use client";

import * as React from "react";
import Image from "next/image";
import { AppHeader } from "./app-header";
import { BrandedAppLoader } from "./branded-app-loader";
import { CommandMenu } from "@/components/navigation/command-menu";
import { siteConfig } from "@/config/site";
import { apiConfig } from "@/config/api";

interface AppShellProps {
  children: React.ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const [commandMenuOpen, setCommandMenuOpen] = React.useState(false);

  return (
    <div className="min-h-screen min-h-[100dvh] flex flex-col bg-cyber-bg text-cyber-text-primary selection:bg-cyber-accent/20 selection:text-white">
      {/* Branded Application Initialization Loader */}
      <BrandedAppLoader />

      {/* Background Architectural Grid Lines */}
      <div className="pointer-events-none fixed inset-0 opacity-[0.025] bg-structural-grid z-0" />

      {/* Global Command Search Overlay */}
      <CommandMenu
        open={commandMenuOpen}
        onOpenChange={setCommandMenuOpen}
      />

      {/* Persistent Horizontal Navigation Header */}
      <AppHeader onOpenCommandMenu={() => setCommandMenuOpen(true)} />

      {/* Primary Application Workspace */}
      <main className="relative z-10 flex-1 flex flex-col w-full">{children}</main>

      {/* Persistent Monolithic Tactical Footer */}
      <footer className="relative z-10 border-t border-cyber-border bg-cyber-bg-secondary py-3 text-[11px] font-mono text-cyber-text-dim mt-auto w-full">
        <div className="w-full px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Image
              src="/images/cybercore-logo-symbol.png"
              alt=""
              width={16}
              height={14}
              className="h-3.5 w-auto object-contain opacity-80"
            />
            <span className="font-semibold text-cyber-text-primary">
              {siteConfig.name}
            </span>
            <span>{"//"}</span>
            <span>AI-ASSISTED CYBERSECURITY INTEL</span>
          </div>

          <div className="flex items-center gap-4 text-[10px]">
            <span>BUS: {apiConfig.baseUrl}</span>
            <span>{"//"}</span>
            <button
              type="button"
              onClick={() => setCommandMenuOpen(true)}
              className="text-cyber-accent hover:underline focus:outline-none"
            >
              COMMAND PALETTE (⌘K)
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}

