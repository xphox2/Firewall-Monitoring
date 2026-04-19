/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./web/**/*.html",
    "./cmd/api/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        // GitHub dark theme colors
        bg: {
          DEFAULT: '#0d1117',
          primary: '#161b22',
          secondary: '#21262d',
          tertiary: '#30363d',
        },
        border: {
          DEFAULT: '#30363d',
          secondary: '#21262d',
        },
        text: {
          primary: '#e6edf3',
          secondary: '#c9d1d9',
          muted: '#8b949e',
          subtle: '#484f58',
        },
        accent: {
          DEFAULT: '#58a6ff',
          hover: '#388bfd',
        },
        success: '#3fb950',
        danger: '#f85149',
        warning: '#d2992a',
        info: '#58a6ff',
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['SFMono-Regular', 'Consolas', 'Liberation Mono', 'Menlo', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease',
        'pulse-slow': 'pulse 2s infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
