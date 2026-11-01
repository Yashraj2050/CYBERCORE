"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  Search,
  Compass,
  Shield,
  FileCode,
  Globe,
  Bot,
  Lock,
  ArrowRight,
  Flame,
  Radio,
  FileSearch,
} from "lucide-react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { mainNavItems } from "@/config/navigation";
import { Badge } from "@/components/ui/badge";
import { cn, detectIoc } from "@/lib/utils";

interface CommandMenuProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface CommandItem {
  id: string;
  title: string;
  subtitle: string;
  icon: React.ComponentType<{ className?: string }>;
  href: string;
  category: "NAVIGATION" | "SECURITY_TOOLS" | "IOC_LOOKUP";
  shortcut?: string;
}

const toolItems: CommandItem[] = [
  {
    id: "tool-scanner",
    title: "Website URL Scanner",
    subtitle: "SSRF-protected threat intelligence & SSL check",
    icon: Globe,
    href: "/security-tools/url-scanner",
    category: "SECURITY_TOOLS",
  },
  {
    id: "tool-message",
    title: "Message Phishing Analyzer",
    subtitle: "Heuristic indicators, urgency tactics & fake OTP fraud",
    icon: Shield,
    href: "/security-tools/message-analyzer",
    category: "SECURITY_TOOLS",
  },
  {
    id: "tool-ip-domain",
    title: "IP & Domain Intelligence",
    subtitle: "Reverse DNS PTR, authoritative DNS & RDAP metadata",
    icon: Radio,
    href: "/security-tools/ip-domain-analyzer",
    category: "SECURITY_TOOLS",
  },
  {
    id: "tool-files-upload",
    title: "File Upload & Header Analyzer",
    subtitle: "Magic bytes, disguised extensions & signature hashes",
    icon: FileSearch,
    href: "/security-tools?tool=files-upload",
    category: "SECURITY_TOOLS",
  },
  {
    id: "tool-files-hash",
    title: "File Hash Threat Check",
    subtitle: "Privacy-first signature check for MD5, SHA-1 & SHA-256",
    icon: FileSearch,
    href: "/security-tools?tool=files-hash",
    category: "SECURITY_TOOLS",
  },
  {
    id: "tool-password",
    title: "Password Breach Verifier",
    subtitle: "k-Anonymity SHA-1 lookup against breach databases",
    icon: Lock,
    href: "/security-tools?tool=password",
    category: "SECURITY_TOOLS",
  },
];

export function CommandMenu({ open, onOpenChange }: CommandMenuProps) {
  const router = useRouter();
  const [search, setSearch] = React.useState("");
  const [selectedIndex, setSelectedIndex] = React.useState(0);
  const inputRef = React.useRef<HTMLInputElement>(null);

  // Keyboard shortcut listener (Cmd+K / Ctrl+K)
  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if ((e.key === "k" && (e.metaKey || e.ctrlKey)) || (e.key === "/" && !e.metaKey && !e.ctrlKey && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement))) {
        e.preventDefault();
        onOpenChange(!open);
      }
    };

    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, [open, onOpenChange]);

  // Combine items
  const allItems = React.useMemo<CommandItem[]>(() => {
    const nav: CommandItem[] = mainNavItems.map((item) => ({
      id: `nav-${item.href}`,
      title: item.title,
      subtitle: item.description,
      icon: item.href === "/" ? Compass : item.href === "/assistant" ? Bot : item.href === "/threat-intelligence" ? Flame : Shield,
      href: item.href,
      category: "NAVIGATION",
      shortcut: item.shortcut,
    }));

    const items = [...nav, ...toolItems];

    if (search.trim().length > 0) {
      const q = search.toLowerCase().trim();
      const filtered = items.filter(
        (it) =>
          it.title.toLowerCase().includes(q) ||
          it.subtitle.toLowerCase().includes(q)
      );

      // Precision Indicator of Compromise (IOC) Detection
      const iocMatch = detectIoc(search);
      if (iocMatch) {
        const targetHref =
          iocMatch.type === "URL"
            ? `/security-tools/url-scanner?query=${encodeURIComponent(iocMatch.query)}`
            : iocMatch.type === "IPv4" || iocMatch.type === "IPv6" || iocMatch.type === "Domain"
            ? `/security-tools/ip-domain-analyzer?query=${encodeURIComponent(iocMatch.query)}`
            : `/security-tools?query=${encodeURIComponent(iocMatch.query)}`;

        filtered.unshift({
          id: `ioc-${iocMatch.type}-${iocMatch.query}`,
          title: `Analyze ${iocMatch.label}`,
          subtitle: iocMatch.description,
          icon: FileCode,
          href: targetHref,
          category: "IOC_LOOKUP",
        });
      }

      return filtered;
    }

    return items;
  }, [search]);

  // Reset selected index when items change
  React.useEffect(() => {
    setSelectedIndex(0);
  }, [allItems]);

  const selectItem = (item: CommandItem) => {
    onOpenChange(false);
    setSearch("");
    router.push(item.href);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (allItems.length || 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) =>
        prev === 0 ? Math.max(allItems.length - 1, 0) : prev - 1
      );
    } else if (e.key === "Enter" && allItems[selectedIndex]) {
      e.preventDefault();
      selectItem(allItems[selectedIndex]);
    }
  };

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/50 dark:bg-[#060709]/80 backdrop-blur-sm animate-in fade-in-0" />
        <DialogPrimitive.Content
          className="fixed left-[50%] top-[20%] z-50 w-full max-w-xl -translate-x-1/2 border border-cyber-border-strong liquid-glass shadow-elevated rounded-xs overflow-hidden animate-in fade-in-0 zoom-in-95"
          onKeyDown={handleKeyDown}
        >
          {/* Brutalist Corner Markers */}
          <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent" />
          <span className="pointer-events-none absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyber-accent" />
          <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent" />
          <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyber-accent" />

          {/* Search Header */}
          <div className="flex items-center border-b border-cyber-border/70 px-3 py-2.5">
            <Search className="h-4 w-4 text-cyber-text-dim mr-2 shrink-0" />
            <input
              ref={inputRef}
              id="command-search-input"
              name="commandSearchQuery"
              aria-label="Search platform tools or enter indicator"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search platform, tools, or enter IOC (IP, domain, hash)..."
              className="w-full bg-transparent text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim focus:outline-none"
              autoFocus
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch("")}
                className="text-[10px] font-mono text-cyber-text-dim hover:text-cyber-text-primary uppercase mr-2"
              >
                Clear
              </button>
            )}
            <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono text-cyber-text-dim bg-cyber-bg border border-cyber-border rounded-none uppercase select-none">
              ESC
            </kbd>
          </div>

          {/* Results List */}
          <div className="max-h-80 overflow-y-auto p-1.5 divide-y divide-cyber-border/30">
            {allItems.length === 0 ? (
              <div className="py-8 text-center text-xs font-mono text-cyber-text-dim">
                No matching tools, routes, or indicators found.
              </div>
            ) : (
              <div className="space-y-0.5">
                {allItems.map((item, idx) => {
                  const Icon = item.icon;
                  const isSelected = idx === selectedIndex;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => selectItem(item)}
                      onMouseEnter={() => setSelectedIndex(idx)}
                      className={cn(
                        "w-full flex items-center justify-between px-3 py-2 text-left rounded-xs transition-colors",
                        isSelected
                          ? "bg-cyber-bg-surface text-cyber-text-primary border-l-2 border-cyber-accent"
                          : "text-cyber-text-secondary hover:bg-cyber-bg-surface/50"
                      )}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <Icon
                          className={cn(
                            "h-3.5 w-3.5 shrink-0",
                            isSelected
                              ? "text-cyber-accent"
                              : "text-cyber-text-dim"
                          )}
                        />
                        <div className="min-w-0">
                          <p className="text-xs font-mono font-medium truncate">
                            {item.title}
                          </p>
                          <p className="text-[10px] text-cyber-text-dim truncate">
                            {item.subtitle}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0 ml-2">
                        {item.category === "IOC_LOOKUP" && (
                          <Badge variant="critical" radius="xs">
                            IOC TARGET
                          </Badge>
                        )}
                        {item.shortcut && (
                          <kbd className="hidden sm:inline-block text-[9px] font-mono text-cyber-text-dim bg-cyber-bg px-1 py-0.5 border border-cyber-border">
                            {item.shortcut}
                          </kbd>
                        )}
                        <ArrowRight className="h-3 w-3 text-cyber-text-dim" />
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Footer Guide */}
          <div className="border-t border-cyber-border/70 bg-cyber-bg/50 px-3 py-1.5 flex items-center justify-between text-[10px] font-mono text-cyber-text-dim">
            <div className="flex items-center gap-3">
              <span>↑↓ Navigate</span>
              <span>↵ Open</span>
              <span>ESC Dismiss</span>
            </div>
            <span>CYBERCORE COMMAND BUS</span>
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
