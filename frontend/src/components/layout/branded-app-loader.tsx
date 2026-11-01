"use client";

import * as React from "react";
import Image from "next/image";

interface BrandedAppLoaderProps {
  isInitialized?: boolean;
  onInitialized?: () => void;
}

export interface CybercoreLoaderMetrics {
  mountedAt: number;
  domReadyAt: number | null;
  fontsReadyAt: number | null;
  minDurationElapsedAt: number | null;
  appReadyAt: number | null;
  dismissalStartedAt: number | null;
  dismissalCompletedAt: number | null;
  totalVisibleDurationMs: number | null;
  isDismissed: boolean;
  themeAtMount: string;
}

declare global {
  interface Window {
    __CYBERCORE_LOADER_METRICS__?: CybercoreLoaderMetrics;
  }
}

/**
 * Minimum visible duration in milliseconds for the branded initialization experience.
 * Must be at least 2,500ms on cold load or hard refresh.
 */
const MINIMUM_DISPLAY_MS = 2500;

/**
 * Maximum safety timeout before forcing app readiness, preventing a permanently stuck loader.
 */
const MAX_FALLBACK_TIMEOUT_MS = 6000;

/**
 * Duration of the fade-out exit transition in milliseconds.
 */
const FADE_OUT_DURATION_MS = 500;

/**
 * Module-level memory flag:
 * - Starts as false when JavaScript runtime loads (initial visit, hard refresh, full reload).
 * - Switches to true once initial branded loader completes.
 * - Persists across all client-side Next.js SPA route navigations within the session.
 */
let hasAppCompletedInitialLoad = false;

type LoaderPhase = "MOUNTED" | "FADING_OUT" | "DISMISSED";

export function BrandedAppLoader({ isInitialized, onInitialized }: BrandedAppLoaderProps) {
  // Allow visual inspection via query parameter for audit / QA verification
  const isPreviewMode = React.useMemo(() => {
    if (typeof window !== "undefined") {
      try {
        return new URLSearchParams(window.location.search).has("preview_loader");
      } catch {
        return false;
      }
    }
    return false;
  }, []);

  const isFrozen = React.useMemo(() => {
    if (typeof window !== "undefined") {
      try {
        return new URLSearchParams(window.location.search).get("preview_loader") === "freeze";
      } catch {
        return false;
      }
    }
    return false;
  }, []);

  // Single authoritative lifecycle state machine
  const [phase, setPhase] = React.useState<LoaderPhase>(() => {
    if (isPreviewMode) return "MOUNTED";
    return hasAppCompletedInitialLoad ? "DISMISSED" : "MOUNTED";
  });

  const onInitializedRef = React.useRef(onInitialized);
  onInitializedRef.current = onInitialized;

  const isInitializedPropRef = React.useRef(isInitialized);
  isInitializedPropRef.current = isInitialized;

  // Track prefers-reduced-motion
  const [prefersReducedMotion, setPrefersReducedMotion] = React.useState(false);

  React.useEffect(() => {
    if (typeof window !== "undefined") {
      const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
      setPrefersReducedMotion(mediaQuery.matches);
      const listener = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
      mediaQuery.addEventListener("change", listener);
      return () => mediaQuery.removeEventListener("change", listener);
    }
  }, []);

  // Clean up legacy sessionStorage key if present
  React.useEffect(() => {
    try {
      if (typeof window !== "undefined" && window.sessionStorage) {
        window.sessionStorage.removeItem("cybercore_app_initialized");
      }
    } catch {
      // ignore
    }
  }, []);

  // Authoritative lifecycle controller (runs once on mount)
  React.useEffect(() => {
    // If already dismissed in module scope and not in preview mode, don't execute
    if (hasAppCompletedInitialLoad && !isPreviewMode) {
      setPhase("DISMISSED");
      return;
    }

    const mountedAt = typeof performance !== "undefined" ? performance.now() : Date.now();

    // Lock body scrolling during active loader display
    if (typeof document !== "undefined") {
      document.body.style.overflow = "hidden";
    }

    // Initialize telemetry metrics
    if (typeof window !== "undefined") {
      window.__CYBERCORE_LOADER_METRICS__ = {
        mountedAt,
        domReadyAt: null,
        fontsReadyAt: null,
        minDurationElapsedAt: null,
        appReadyAt: null,
        dismissalStartedAt: null,
        dismissalCompletedAt: null,
        totalVisibleDurationMs: null,
        isDismissed: false,
        themeAtMount: document.documentElement.className || "unknown",
      };
    }

    let minTimeElapsed = false;
    let appReady = false;
    let isFadingOut = false;

    let minTimer: NodeJS.Timeout | null = null;
    let fallbackTimer: NodeJS.Timeout | null = null;
    let exitTimer: NodeJS.Timeout | null = null;

    const cleanupScrollLock = () => {
      if (typeof document !== "undefined") {
        document.body.style.removeProperty("overflow");
        document.body.style.removeProperty("pointer-events");
        document.documentElement.style.removeProperty("overflow");
      }
    };

    const tryDismiss = () => {
      if (isFrozen) return;
      if (!minTimeElapsed || !appReady || isFadingOut) return;
      isFadingOut = true;

      const dismissStart = typeof performance !== "undefined" ? performance.now() : Date.now();
      if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
        window.__CYBERCORE_LOADER_METRICS__.dismissalStartedAt = dismissStart;
      }

      setPhase("FADING_OUT");

      const exitDuration = prefersReducedMotion ? 0 : FADE_OUT_DURATION_MS;

      exitTimer = setTimeout(() => {
        const completeTime = typeof performance !== "undefined" ? performance.now() : Date.now();
        if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
          window.__CYBERCORE_LOADER_METRICS__.dismissalCompletedAt = completeTime;
          window.__CYBERCORE_LOADER_METRICS__.totalVisibleDurationMs = completeTime - mountedAt;
          window.__CYBERCORE_LOADER_METRICS__.isDismissed = true;
        }

        hasAppCompletedInitialLoad = true;
        setPhase("DISMISSED");
        cleanupScrollLock();

        if (onInitializedRef.current) {
          onInitializedRef.current();
        }
      }, exitDuration);
    };

    // 1. Minimum display duration timer: strictly guarantees at least 2,500ms
    minTimer = setTimeout(() => {
      minTimeElapsed = true;
      if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
        window.__CYBERCORE_LOADER_METRICS__.minDurationElapsedAt =
          typeof performance !== "undefined" ? performance.now() : Date.now();
      }
      tryDismiss();
    }, MINIMUM_DISPLAY_MS);

    // 2. Track application readiness independently
    const evaluateReadiness = async () => {
      // If explicit isInitialized prop is passed
      if (isInitializedPropRef.current !== undefined) {
        if (isInitializedPropRef.current) {
          appReady = true;
          if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
            window.__CYBERCORE_LOADER_METRICS__.appReadyAt =
              typeof performance !== "undefined" ? performance.now() : Date.now();
          }
          tryDismiss();
        }
        return;
      }

      // Check DOM readiness
      if (typeof document !== "undefined") {
        if (document.readyState === "complete" || document.readyState === "interactive") {
          if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
            window.__CYBERCORE_LOADER_METRICS__.domReadyAt =
              typeof performance !== "undefined" ? performance.now() : Date.now();
          }
        } else {
          await new Promise<void>((resolve) => {
            const handleReady = () => resolve();
            document.addEventListener("DOMContentLoaded", handleReady, { once: true });
            window.addEventListener("load", handleReady, { once: true });
          });
          if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
            window.__CYBERCORE_LOADER_METRICS__.domReadyAt =
              typeof performance !== "undefined" ? performance.now() : Date.now();
          }
        }

        // Wait for web fonts so no text shifts occur
        if ("fonts" in document && document.fonts && typeof document.fonts.ready?.then === "function") {
          try {
            await document.fonts.ready;
            if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
              window.__CYBERCORE_LOADER_METRICS__.fontsReadyAt =
                typeof performance !== "undefined" ? performance.now() : Date.now();
            }
          } catch {
            // Ignore font loading errors
          }
        }

        appReady = true;
        if (typeof window !== "undefined" && window.__CYBERCORE_LOADER_METRICS__) {
          window.__CYBERCORE_LOADER_METRICS__.appReadyAt =
            typeof performance !== "undefined" ? performance.now() : Date.now();
        }
        tryDismiss();
      }
    };

    evaluateReadiness();

    // 3. Fallback safety timer: prevents indefinite hang if assets/network stall
    fallbackTimer = setTimeout(() => {
      minTimeElapsed = true;
      appReady = true;
      tryDismiss();
    }, MAX_FALLBACK_TIMEOUT_MS);

    return () => {
      if (minTimer) clearTimeout(minTimer);
      if (fallbackTimer) clearTimeout(fallbackTimer);
      if (exitTimer) clearTimeout(exitTimer);
      cleanupScrollLock();
    };
  }, [isPreviewMode, isFrozen, prefersReducedMotion]);

  if (phase === "DISMISSED") {
    return null;
  }

  const isFading = phase === "FADING_OUT";

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Initializing CyberCore"
      className={`fixed inset-0 z-[100] flex flex-col items-center justify-center bg-cyber-bg transition-all duration-500 ease-out motion-reduce:transition-none selection:bg-transparent ${
        isFading ? "opacity-0 pointer-events-none scale-[1.01]" : "opacity-100 scale-100"
      }`}
    >
      {/* Subtle Background Architectural Grid */}
      <div className="pointer-events-none absolute inset-0 opacity-[0.035] bg-structural-grid" />

      {/* Monolithic Tactical Corner Framing */}
      <div className="pointer-events-none absolute inset-6 sm:inset-10 border border-cyber-border/40">
        <span className="absolute -top-[1px] -left-[1px] w-3 h-3 border-t-2 border-l-2 border-cyber-accent" />
        <span className="absolute -top-[1px] -right-[1px] w-3 h-3 border-t-2 border-r-2 border-cyber-accent" />
        <span className="absolute -bottom-[1px] -left-[1px] w-3 h-3 border-b-2 border-l-2 border-cyber-accent" />
        <span className="absolute -bottom-[1px] -right-[1px] w-3 h-3 border-b-2 border-r-2 border-cyber-accent" />
      </div>

      {/* Center Branded Presentation */}
      <div
        className={`relative z-10 flex flex-col items-center justify-center px-6 text-center space-y-8 max-w-sm sm:max-w-md transition-opacity duration-500 ease-out motion-reduce:transition-none ${
          isFading ? "opacity-0" : "opacity-100"
        }`}
      >
        {/* Official CYBERCORE Full Logo with smooth reveal (Theme adaptive) */}
        <div className="relative w-64 sm:w-80 h-16 sm:h-20 animate-logo-reveal motion-reduce:animate-none">
          <Image
            src="/images/cybercore-logo-full.png"
            alt="CYBERCORE"
            width={400}
            height={81}
            priority
            className="w-full h-full object-contain filter drop-shadow-[0_0_24px_rgba(182,199,217,0.15)] hidden dark:block"
          />
          <Image
            src="/images/cybercore-logo-full-light.png"
            alt="CYBERCORE"
            width={400}
            height={81}
            priority
            className="w-full h-full object-contain filter drop-shadow-[0_4px_24px_rgba(15,23,42,0.08)] block dark:hidden"
          />
        </div>

        {/* Tactical Loading Telemetry Container */}
        <div className="w-full max-w-[260px] space-y-4 pt-2">
          {/* Restrained Steel-Blue Progress Line */}
          <div className="w-full h-[1.5px] bg-cyber-border-strong overflow-hidden relative">
            <div className="absolute inset-y-0 h-full w-1/3 bg-gradient-to-r from-transparent via-cyber-accent to-transparent animate-loader-shimmer motion-reduce:animate-none" />
          </div>

          {/* Status Typography */}
          <div className="space-y-1 font-mono">
            <div className="text-[10px] tracking-[0.25em] text-cyber-accent uppercase font-medium">
              INITIALIZING CYBERCORE
            </div>
            <div className="text-[8.5px] tracking-[0.2em] text-cyber-text-dim uppercase">
              SECURE INVESTIGATION ENVIRONMENT
            </div>
          </div>
        </div>
      </div>

      {/* Screen-reader status message */}
      <span className="sr-only">CyberCore secure investigation platform initialized</span>
    </div>
  );
}
