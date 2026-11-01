import * as React from "react";
import { cn } from "@/lib/utils";

export interface PageHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  title: string;
  description?: string;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  editorialTag?: string;
}

export function PageHeader({
  title,
  description,
  badge,
  actions,
  editorialTag,
  className,
  ...props
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        "relative glass-panel p-5 sm:p-7 rounded-xs shadow-elevated overflow-hidden border border-cyber-border",
        className
      )}
      {...props}
    >
      {/* Corner Brutalist Markers */}
      <span className="pointer-events-none absolute top-0 left-0 w-2.5 h-2.5 border-t-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute top-0 right-0 w-2.5 h-2.5 border-t-2 border-r-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 left-0 w-2.5 h-2.5 border-b-2 border-l-2 border-cyber-accent" />
      <span className="pointer-events-none absolute bottom-0 right-0 w-2.5 h-2.5 border-b-2 border-r-2 border-cyber-accent" />

      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1.5">
          {editorialTag && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono tracking-tactical text-cyber-accent uppercase font-medium">
                {editorialTag}
              </span>
            </div>
          )}

          <div className="flex items-center gap-3">
            <h1 className="text-xl sm:text-2xl font-mono font-bold tracking-monolithic text-cyber-text-primary uppercase">
              {title}
            </h1>
            {badge && <div className="shrink-0">{badge}</div>}
          </div>

          {description && (
            <p className="text-xs sm:text-sm text-cyber-text-secondary max-w-3xl leading-relaxed font-sans">
              {description}
            </p>
          )}
        </div>

        {actions && <div className="flex items-center gap-2.5 shrink-0 pt-2 md:pt-0">{actions}</div>}
      </div>
    </div>
  );
}
