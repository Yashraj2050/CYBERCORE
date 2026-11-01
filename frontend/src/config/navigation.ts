/**
 * CYBERCORE Application Navigation Configuration
 * Defines core navigation routes and command menu shortcuts.
 */

export interface NavItem {
  title: string;
  href: string;
  description: string;
  shortcut?: string;
  badge?: string;
}

export const mainNavItems: NavItem[] = [
  {
    title: "Overview",
    href: "/",
    description: "Security posture, live telemetry & recent verifications",
    shortcut: "G O",
  },
  {
    title: "Investigations",
    href: "/investigations",
    description: "Forensic telemetry, indicator analysis & triage cases",
    shortcut: "G I",
  },
  {
    title: "Threat Intelligence",
    href: "/threat-intelligence",
    description: "Active campaigns, phishing trends & threat actors",
    shortcut: "G T",
  },
  {
    title: "Security Tools",
    href: "/security-tools",
    description: "Website scanner, file hash analyzer & password check",
    shortcut: "G S",
  },
  {
    title: "AI Assistant",
    href: "/assistant",
    description: "AI cybersecurity advisor for triage & risk mitigation",
    shortcut: "G A",
  },
];

