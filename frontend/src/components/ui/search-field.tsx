"use client";

import * as React from "react";
import { Search, X } from "lucide-react";
import { cn } from "@/lib/utils";

export interface SearchFieldProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  onClear?: () => void;
  shortcut?: string;
  containerClassName?: string;
}

const SearchField = React.forwardRef<HTMLInputElement, SearchFieldProps>(
  (
    {
      className,
      containerClassName,
      value,
      onChange,
      onClear,
      shortcut = "⌘K",
      placeholder = "Search threats, IOCs, CVEs, endpoints...",
      id,
      name = "searchQuery",
      "aria-label": ariaLabel = "Search threats and indicators",
      ...props
    },
    ref
  ) => {
    const generatedId = React.useId();
    const inputId = id || generatedId;
    const hasValue = Boolean(value && String(value).length > 0);

    return (
      <div
        className={cn(
          "relative flex items-center w-full bg-cyber-bg-secondary border border-cyber-border rounded-xs transition-colors focus-within:border-cyber-accent focus-within:ring-1 focus-within:ring-cyber-accent",
          containerClassName
        )}
      >
        <Search
          className="absolute left-3 h-3.5 w-3.5 text-cyber-text-dim pointer-events-none shrink-0"
          aria-hidden="true"
        />

        <input
          ref={ref}
          id={inputId}
          name={name}
          aria-label={ariaLabel}
          type="search"
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={cn(
            "w-full h-9 bg-transparent pl-9 pr-14 text-xs font-mono text-cyber-text-primary placeholder:text-cyber-text-dim placeholder:font-sans focus:outline-none disabled:cursor-not-allowed disabled:opacity-40",
            className
          )}
          {...props}
        />

        <div className="absolute right-2.5 flex items-center gap-1.5">
          {hasValue && onClear && (
            <button
              type="button"
              onClick={onClear}
              className="p-0.5 text-cyber-text-dim hover:text-cyber-text-primary transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-cyber-accent"
              aria-label="Clear search query"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}

          {shortcut && !hasValue && (
            <kbd className="pointer-events-none hidden sm:inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono tracking-wider text-cyber-text-dim bg-cyber-bg border border-cyber-border/80 rounded-none uppercase select-none">
              {shortcut}
            </kbd>
          )}
        </div>
      </div>
    );
  }
);
SearchField.displayName = "SearchField";

export { SearchField };
