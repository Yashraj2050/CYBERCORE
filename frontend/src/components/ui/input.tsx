import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const inputVariants = cva(
  "flex w-full bg-cyber-bg-secondary px-3 py-1.5 text-xs text-cyber-text-primary placeholder:text-cyber-text-dim border border-cyber-border transition-colors duration-150 file:border-0 file:bg-transparent file:text-xs file:font-medium focus-visible:outline-none focus-visible:border-cyber-accent focus-visible:ring-1 focus-visible:ring-cyber-accent disabled:cursor-not-allowed disabled:opacity-40",
  {
    variants: {
      variant: {
        default:
          "bg-cyber-bg-secondary border-cyber-border",
        surface:
          "bg-cyber-bg-surface border-cyber-border-strong",
        glass:
          "glass-subtle border-cyber-border focus-visible:border-cyber-accent",
      },
      inputSize: {
        sm: "h-7 text-[11px] px-2.5",
        default: "h-9 text-xs px-3",
        lg: "h-10 text-sm px-3.5",
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
      inputSize: "default",
      radius: "default",
    },
  }
);

export interface InputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "size">,
    VariantProps<typeof inputVariants> {
  error?: boolean;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, variant, inputSize, radius, error, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          inputVariants({ variant, inputSize, radius }),
          error && "border-cyber-threat-critical/80 focus-visible:border-cyber-threat-critical focus-visible:ring-cyber-threat-critical",
          className
        )}
        ref={ref}
        {...props}
      />
    );
  }
);
Input.displayName = "Input";

export { Input, inputVariants };

