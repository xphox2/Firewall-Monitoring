/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          DEFAULT: 'var(--fwmon-bg)',
          card: 'var(--fwmon-card-bg)',
          panel: 'var(--fwmon-panel-bg)',
          hover: 'var(--fwmon-row-hover)',
          elevated: 'var(--fwmon-elevated-bg)',
        },
        border: {
          DEFAULT: 'var(--fwmon-border)',
          subtle: 'var(--fwmon-border-subtle)',
          strong: 'var(--fwmon-border-strong)',
        },
        text: {
          DEFAULT: 'var(--fwmon-text)',
          dim: 'var(--fwmon-text-dim)',
          faint: 'var(--fwmon-text-faint)',
          mute: 'var(--fwmon-text-mute)',
        },
        accent: {
          DEFAULT: 'var(--fwmon-accent)',
          hover: 'var(--fwmon-accent-hover)',
          soft: 'var(--fwmon-accent-soft)',
        },
        sig: {
          ok: 'var(--fwmon-sig-ok)',
          warn: 'var(--fwmon-sig-warn)',
          crit: 'var(--fwmon-sig-crit)',
          info: 'var(--fwmon-sig-info)',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        display: ['Archivo', 'Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
