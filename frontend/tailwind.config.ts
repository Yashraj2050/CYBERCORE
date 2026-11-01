import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    container: {
      center: true,
      padding: {
        DEFAULT: "1rem",
        sm: "1.5rem",
        lg: "2rem",
      },
      screens: {
        sm: "640px",
        md: "768px",
        lg: "1024px",
        xl: "1280px",
        "2xl": "1440px",
      },
    },
    extend: {
      colors: {
        // CYBERCORE Foundation Design Tokens
        cyber: {
          bg: {
            canvas: "var(--bg-canvas)",
            DEFAULT: "var(--bg-primary)",
            secondary: "var(--bg-secondary)",
            tertiary: "var(--bg-tertiary)",
            surface: "var(--bg-surface)",
            elevated: "var(--bg-surface-elevated)",
            panel: "var(--bg-surface-panel)",
            hover: "var(--bg-surface-hover)",
            active: "var(--bg-surface-active)",
          },
          text: {
            primary: "var(--text-primary)",
            secondary: "var(--text-secondary)",
            muted: "var(--text-muted)",
            dim: "var(--text-dim)",
            inverse: "var(--text-inverse)",
          },
          border: {
            subtle: "var(--border-subtle)",
            DEFAULT: "var(--border-default)",
            strong: "var(--border-strong)",
            accent: "var(--border-accent)",
            bright: "var(--border-accent-bright)",
          },
          accent: {
            DEFAULT: "var(--accent-primary)",
            hover: "var(--accent-hover)",
            muted: "var(--accent-muted)",
            deep: "var(--accent-deep)",
            subtle: "var(--accent-subtle)",
            surface: "var(--accent-surface)",
            glow: "var(--accent-glow)",
          },
          threat: {
            critical: {
              DEFAULT: "var(--threat-critical)",
              bg: "var(--threat-critical-bg)",
              border: "var(--threat-critical-border)",
            },
            high: {
              DEFAULT: "var(--threat-high)",
              bg: "var(--threat-high-bg)",
              border: "var(--threat-high-border)",
            },
            medium: {
              DEFAULT: "var(--threat-medium)",
              bg: "var(--threat-medium-bg)",
              border: "var(--threat-medium-border)",
            },
            low: {
              DEFAULT: "var(--threat-low)",
              bg: "var(--threat-low-bg)",
              border: "var(--threat-low-border)",
            },
            info: {
              DEFAULT: "var(--threat-info)",
              bg: "var(--threat-info-bg)",
              border: "var(--threat-info-border)",
            },
            secure: {
              DEFAULT: "var(--threat-secure)",
              bg: "var(--threat-secure-bg)",
              border: "var(--threat-secure-border)",
            },
          },
          status: {
            critical: "var(--status-critical)",
            warning: "var(--status-warning)",
            success: "var(--status-success)",
            info: "var(--status-info)",
          },
        },
        // shadcn/ui HSL mapping
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
      },
      borderRadius: {
        none: "var(--radius-none)",
        xs: "var(--radius-xs)",
        sm: "var(--radius-sm)",
        md: "var(--radius-md)",
        lg: "var(--radius-lg)",
        DEFAULT: "var(--radius)",
      },
      boxShadow: {
        subtle: "var(--shadow-subtle)",
        surface: "var(--shadow-surface)",
        elevated: "var(--shadow-elevated)",
        "accent-glow": "var(--shadow-accent-glow)",
        "glass-panel": "var(--glass-panel-shadow)",
      },
      backdropBlur: {
        sm: "var(--blur-sm)",
        md: "var(--blur-md)",
        lg: "var(--blur-lg)",
      },
      fontFamily: {
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "monospace"],
      },
      letterSpacing: {
        monolithic: "0.15em",
        tactical: "0.08em",
        data: "0.04em",
      },
    },
  },
  plugins: [],
};

export default config;
