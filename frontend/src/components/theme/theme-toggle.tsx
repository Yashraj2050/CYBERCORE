"use client";

import * as React from "react";
import { Sun, Moon } from "lucide-react";
import { useTheme } from "./theme-provider";
import { cn } from "@/lib/utils";

interface ThemeToggleProps {
  className?: string;
  showLabel?: boolean;
}

export function ThemeToggle({ className, showLabel = false }: ThemeToggleProps) {
  const { theme, toggleTheme } = useTheme();
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const isDark = theme === "dark";

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className={cn(
        "relative flex items-center justify-center gap-2 h-8 px-2.5 bg-cyber-bg-secondary hover:bg-cyber-bg-surface border border-cyber-border rounded-xs text-cyber-text-secondary hover:text-cyber-text-primary transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent select-none",
        className
      )}
      aria-label={
        mounted
          ? isDark
            ? "Switch to Arctic Glass light theme"
            : "Switch to Obsidian Luxury dark theme"
          : "Toggle theme"
      }
      title={
        mounted
          ? isDark
            ? "Switch to Arctic Glass light theme"
            : "Switch to Obsidian Luxury dark theme"
          : "Toggle visual theme"
      }
    >
      {/* Sun Icon (Visible when dark to trigger switch to light, or rendered gracefully) */}
      <Sun
        className={cn(
          "h-3.5 w-3.5 transition-transform duration-200 text-amber-500",
          !mounted ? "opacity-0" : isDark ? "block" : "hidden"
        )}
      />

      {/* Moon Icon (Visible when light to trigger switch to dark) */}
      <Moon
        className={cn(
          "h-3.5 w-3.5 transition-transform duration-200 text-cyber-accent",
          !mounted ? "opacity-0" : !isDark ? "block" : "hidden"
        )}
      />

      {/* Fallback placeholder during SSR to prevent layout shift */}
      {!mounted && <span className="h-3.5 w-3.5 block" />}

      {showLabel && (
        <span className="text-xs font-mono uppercase tracking-tactical text-cyber-text-secondary">
          {mounted ? (isDark ? "LIGHT MODE" : "DARK MODE") : "THEME"}
        </span>
      )}
    </button>
  );
}

