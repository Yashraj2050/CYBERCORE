import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 px-2 py-0.5 text-[10px] font-mono tracking-tactical uppercase font-medium border transition-colors select-none",
  {
    variants: {
      variant: {
        default:
          "border-cyber-border-strong bg-cyber-bg-surface text-cyber-text-secondary",
        arctic:
          "border-cyber-accent/30 bg-cyber-accent-subtle text-cyber-accent",
        monolithic:
          "border-cyber-border bg-cyber-bg text-cyber-text-dim hover:text-cyber-text-secondary",
        outline:
          "border-cyber-border/80 bg-transparent text-cyber-text-muted",
        critical:
          "border-cyber-threat-critical-border bg-cyber-threat-critical-bg text-cyber-threat-critical",
        high:
          "border-cyber-threat-high-border bg-cyber-threat-high-bg text-cyber-threat-high",
        medium:
          "border-cyber-threat-medium-border bg-cyber-threat-medium-bg text-cyber-threat-medium",
        low:
          "border-cyber-threat-low-border bg-cyber-threat-low-bg text-cyber-threat-low",
        info:
          "border-cyber-threat-info-border bg-cyber-threat-info-bg text-cyber-threat-info",
        secure:
          "border-cyber-threat-secure-border bg-cyber-threat-secure-bg text-cyber-threat-secure",
      },
      radius: {
        none: "rounded-none",
        xs: "rounded-xs",
        sm: "rounded-sm",
        default: "rounded-xs",
      },
    },
    defaultVariants: {
      variant: "default",
      radius: "default",
    },
  }
);

const dotColors: Record<string, string> = {
  default: "bg-cyber-text-muted",
  arctic: "bg-cyber-accent",
  monolithic: "bg-cyber-text-dim",
  outline: "bg-cyber-text-dim",
  critical: "bg-cyber-threat-critical",
  high: "bg-cyber-threat-high",
  medium: "bg-cyber-threat-medium",
  low: "bg-cyber-threat-low",
  info: "bg-cyber-threat-info",
  secure: "bg-cyber-threat-secure",
};

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {
  dot?: boolean;
}

function Badge({ className, variant = "default", radius, dot = false, children, ...props }: BadgeProps) {
  const activeVariant = variant || "default";
  return (
    <div className={cn(badgeVariants({ variant: activeVariant, radius }), className)} {...props}>
      {dot && (
        <span
          className={cn("h-1.5 w-1.5 rounded-full shrink-0", dotColors[activeVariant] || "bg-cyber-accent")}
          aria-hidden="true"
        />
      )}
      <span>{children}</span>
    </div>
  );
}

export { Badge, badgeVariants };
