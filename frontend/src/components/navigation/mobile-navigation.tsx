"use client";

import * as React from "react";
import Link from "next/link";
import Image from "next/image";
import { usePathname } from "next/navigation";
import {
  Menu,
  X,
  Shield,
  Search,
  Compass,
  Flame,
  Wrench,
  Bot,
} from "lucide-react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { mainNavItems } from "@/config/navigation";
import { Badge } from "@/components/ui/badge";
import { ThemeToggle } from "@/components/theme/theme-toggle";
import { cn } from "@/lib/utils";

interface MobileNavigationProps {
  onOpenCommandMenu: () => void;
  systemStatus?: string;
  isBackendConnected?: boolean;
}

const navIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  "/": Compass,
  "/investigations": Shield,
  "/threat-intelligence": Flame,
  "/security-tools": Wrench,
  "/assistant": Bot,
};

export function MobileNavigation({
  onOpenCommandMenu,
  systemStatus = "OFFLINE",
  isBackendConnected = false,
}: MobileNavigationProps) {
  const [open, setOpen] = React.useState(false);
  const pathname = usePathname();

  // Close drawer upon route change
  React.useEffect(() => {
    setOpen(false);
  }, [pathname]);

  return (
    <div className="lg:hidden flex items-center gap-2">
      {/* Theme Toggle accessible right on mobile bar */}
      <ThemeToggle />

      <DialogPrimitive.Root open={open} onOpenChange={setOpen}>
        <DialogPrimitive.Trigger asChild>
          <button
            type="button"
            className="flex items-center justify-center h-8 w-8 bg-cyber-bg-secondary hover:bg-cyber-bg-surface border border-cyber-border rounded-xs text-cyber-text-secondary hover:text-cyber-text-primary transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent"
            aria-label="Open main menu"
          >
            <Menu className="h-4 w-4" />
          </button>
        </DialogPrimitive.Trigger>

        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/50 dark:bg-[#060709]/85 backdrop-blur-sm animate-in fade-in-0" />
          <DialogPrimitive.Content className="fixed inset-y-0 right-0 z-50 w-full max-w-xs border-l border-cyber-border-strong bg-cyber-bg-secondary p-5 shadow-elevated flex flex-col justify-between animate-in slide-in-from-right duration-200">
            {/* Brutalist Corner Markers */}
            <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent" />
            <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent" />

            <div className="space-y-6">
              {/* Header */}
              <div className="flex items-center justify-between border-b border-cyber-border/60 pb-4">
                <Link
                  href="/"
                  onClick={() => setOpen(false)}
                  className="flex items-center focus:outline-none"
                  aria-label="CYBERCORE Dashboard"
                >
                  <Image
                    src="/images/cybercore-logo-full.png"
                    alt="CYBERCORE"
                    width={130}
                    height={26}
                    className="h-6 w-auto object-contain hidden dark:block"
                  />
                  <Image
                    src="/images/cybercore-logo-full-light.png"
                    alt="CYBERCORE"
                    width={130}
                    height={26}
                    className="h-6 w-auto object-contain block dark:hidden"
                  />
                </Link>

                <DialogPrimitive.Close className="p-1 text-cyber-text-dim hover:text-cyber-text-primary focus:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent">
                  <X className="h-4 w-4" />
                  <span className="sr-only">Close menu</span>
                </DialogPrimitive.Close>
              </div>

              {/* Quick Search Action */}
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onOpenCommandMenu();
                }}
                className="w-full flex items-center justify-between px-3 py-2 bg-cyber-bg border border-cyber-border rounded-xs text-xs font-mono text-cyber-text-dim hover:text-cyber-text-secondary transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Search className="h-3.5 w-3.5 text-cyber-accent" />
                  <span>Search or command...</span>
                </div>
                <kbd className="px-1.5 py-0.5 text-[9px] font-mono text-cyber-text-dim bg-cyber-bg-surface border border-cyber-border rounded-none">
                  ⌘K
                </kbd>
              </button>

              {/* Navigation Links */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono uppercase tracking-tactical text-cyber-text-dim block px-1 mb-2">
                  NAVIGATION SECTIONS
                </span>
                {mainNavItems.map((item) => {
                  const Icon = navIcons[item.href] || Compass;
                  const isActive =
                    item.href === "/"
                      ? pathname === "/" || pathname === "/dashboard"
                      : pathname.startsWith(item.href);

                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2.5 rounded-xs text-xs font-mono tracking-tactical uppercase transition-colors",
                        isActive
                          ? "bg-cyber-bg-surface text-cyber-text-primary border-l-2 border-cyber-accent font-semibold"
                          : "text-cyber-text-secondary hover:text-cyber-text-primary hover:bg-cyber-bg-surface/50"
                      )}
                    >
                      <Icon
                        className={cn(
                          "h-4 w-4",
                          isActive ? "text-cyber-accent" : "text-cyber-text-dim"
                        )}
                      />
                      <span>{item.title}</span>
                    </Link>
                  );
                })}
              </div>
            </div>

            {/* Footer Telemetry */}
            <div className="border-t border-cyber-border/60 pt-4 space-y-3">
              <div className="flex items-center justify-between text-[11px] font-mono">
                <span className="text-cyber-text-dim">SYSTEM BUS:</span>
                <Badge
                  variant={isBackendConnected ? "secure" : "default"}
                  radius="xs"
                  dot
                >
                  {isBackendConnected ? systemStatus : "OFFLINE"}
                </Badge>
              </div>
              <p className="text-[10px] font-mono text-cyber-text-dim text-center">
                CYBERCORE // MONOLITHIC HORIZONTAL OS
              </p>
            </div>
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
    </div>
  );
}
