"use client";

import * as React from "react";
import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import {
  Shield,
  Search,
  SlidersHorizontal,
  Terminal,
  Activity,
  UserCheck,
  ChevronDown,
} from "lucide-react";
import { mainNavItems } from "@/config/navigation";
import { siteConfig } from "@/config/site";
import { apiConfig } from "@/config/api";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
} from "@/components/ui/dropdown-menu";
import { ThemeToggle } from "@/components/theme/theme-toggle";
import { cn } from "@/lib/utils";

interface TopNavigationProps {
  onOpenCommandMenu: () => void;
  systemStatus?: "OPERATIONAL" | "ACTIVE_DEFENSE" | "DEGRADED" | "OFFLINE" | string;
  isBackendConnected?: boolean;
}

export function TopNavigation({
  onOpenCommandMenu,
  systemStatus = "OFFLINE",
  isBackendConnected = false,
}: TopNavigationProps) {
  const pathname = usePathname();

  return (
    <nav className="h-14 w-full flex items-center justify-between gap-4">
      {/* ====================================================================
          LEFT: Official CYBERCORE Logo & Wordmark (Theme-Adaptive)
          ==================================================================== */}
      <div className="flex items-center gap-3 shrink-0">
        <Link
          href="/"
          className="flex items-center group focus:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent rounded-xs py-1"
          aria-label="CYBERCORE Platform Overview"
        >
          {/* Desktop & Tablet: Full horizontal official logo */}
          <div className="hidden sm:flex items-center">
            {/* Dark Mode Logo (White typography) */}
            <Image
              src="/images/cybercore-logo-full.png"
              alt="CYBERCORE"
              width={148}
              height={30}
              priority
              className="h-[26px] w-auto object-contain transition-opacity duration-150 group-hover:opacity-85 hidden dark:block"
            />
            {/* Light Mode Logo (Arctic Charcoal typography) */}
            <Image
              src="/images/cybercore-logo-full-light.png"
              alt="CYBERCORE"
              width={148}
              height={30}
              priority
              className="h-[26px] w-auto object-contain transition-opacity duration-150 group-hover:opacity-85 block dark:hidden"
            />
          </div>

          {/* Mobile: Standalone symbol */}
          <div className="flex sm:hidden items-center">
            <Image
              src="/images/cybercore-logo-symbol.png"
              alt="CYBERCORE"
              width={32}
              height={28}
              priority
              className="h-7 w-auto object-contain transition-opacity duration-150 group-hover:opacity-85"
            />
          </div>
        </Link>
      </div>

      {/* ====================================================================
          CENTER: Primary Navigation Links (Desktop)
          ==================================================================== */}
      <div className="hidden lg:flex items-center gap-1 xl:gap-2">
        {mainNavItems.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/" || pathname === "/dashboard"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "relative px-3 py-1.5 text-xs font-mono tracking-tactical uppercase transition-all rounded-xs select-none",
                isActive
                  ? "text-cyber-text-primary font-semibold bg-cyber-bg-surface/80 border border-cyber-border-strong shadow-subtle"
                  : "text-cyber-text-secondary hover:text-cyber-text-primary hover:bg-cyber-bg-surface/40 border border-transparent"
              )}
            >
              {isActive && (
                <span className="absolute bottom-0 left-2 right-2 h-[2px] bg-cyber-accent" />
              )}
              {item.title}
            </Link>
          );
        })}
      </div>

      {/* ====================================================================
          RIGHT: Command Search Trigger, Status Telemetry & Theme Switcher
          ==================================================================== */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        {/* Global Command Search Trigger */}
        <button
          type="button"
          onClick={onOpenCommandMenu}
          className="flex items-center gap-2 px-2.5 py-1.5 h-8 bg-cyber-bg-secondary hover:bg-cyber-bg-surface border border-cyber-border rounded-xs text-xs font-mono text-cyber-text-dim hover:text-cyber-text-secondary transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent"
          aria-label="Open global command search"
        >
          <Search className="h-3.5 w-3.5 text-cyber-accent" />
          <span className="hidden md:inline text-[11px] tracking-wide">
            Search or command...
          </span>
          <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono text-cyber-text-dim bg-cyber-bg border border-cyber-border rounded-none uppercase">
            ⌘K
          </kbd>
        </button>

        {/* Real Backend Telemetry Indicator (No fake indicators) */}
        <div className="hidden xl:flex items-center gap-1.5 px-2 py-1 bg-cyber-bg border border-cyber-border rounded-xs">
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full shrink-0",
              isBackendConnected ? "bg-emerald-500" : "bg-cyber-text-dim"
            )}
            aria-hidden="true"
          />
          <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-text-dim">
            {isBackendConnected ? systemStatus : "BACKEND STANDBY"}
          </span>
        </div>

        {/* Theme Switcher Toggle (Sun / Moon) */}
        <ThemeToggle />

        {/* User / Operator Control Dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className="flex items-center gap-1.5 px-2 py-1 bg-cyber-bg-secondary hover:bg-cyber-bg-surface border border-cyber-border rounded-xs text-xs font-mono text-cyber-text-secondary focus:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent transition-colors"
            >
              <div className="h-5 w-5 bg-cyber-accent-subtle border border-cyber-accent/40 rounded-xs flex items-center justify-center text-[10px] font-bold text-cyber-accent">
                OP
              </div>
              <span className="hidden sm:inline text-[11px] font-medium text-cyber-text-primary">
                SEC-OPS
              </span>
              <ChevronDown className="h-3 w-3 text-cyber-text-dim" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>OPERATOR PROFILE</DropdownMenuLabel>
            <div className="px-2.5 py-1 text-[10px] font-mono text-cyber-text-dim space-y-0.5 border-b border-cyber-border/40 pb-2 mb-1">
              <p className="text-cyber-text-primary">AUTHORITY: ANALYST-TIER-1</p>
              <p className="truncate">BASE: {apiConfig.baseUrl}</p>
            </div>
            <DropdownMenuItem onClick={onOpenCommandMenu}>
              Command Palette
              <DropdownMenuShortcut>⌘K</DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href="/security-tools">Launch Security Tools</Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/assistant">Consult AI Advisor</Link>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </nav>
  );
}
