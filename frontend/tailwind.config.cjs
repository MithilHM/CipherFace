/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Core Palette
        'bg-deep': 'var(--bg-deep)',
        'bg-dark': 'var(--bg-dark)',
        'bg-elevated': 'var(--bg-elevated)',

        // Surface
        surface: 'var(--surface)',
        'surface-hover': 'var(--surface-hover)',
        'surface-active': 'var(--surface-active)',

        // Primary
        primary: 'var(--primary)',
        'primary-light': 'var(--primary-light)',
        'primary-dark': 'var(--primary-dark)',
        'primary-glow': 'var(--primary-glow)',

        // Accent
        accent: 'var(--accent)',
        'accent-light': 'var(--accent-light)',
        'accent-dark': 'var(--accent-dark)',
        'accent-glow': 'var(--accent-glow)',

        // Secondary
        cyan: 'var(--cyan)',
        'cyan-glow': 'var(--cyan-glow)',
        pink: 'var(--pink)',
        'pink-glow': 'var(--pink-glow)',

        // Text
        'text-main': 'var(--text-main)',
        'text-secondary': 'var(--text-secondary)',
        'text-muted': 'var(--text-muted)',
        'text-dim': 'var(--text-dim)',

        // Status
        success: 'var(--success)',
        warning: 'var(--warning)',
        error: 'var(--error)',
        info: 'var(--info)',

        // Glass
        'glass-border': 'var(--glass-border)',
        'glass-border-hover': 'var(--glass-border-hover)',
        'glass-highlight': 'var(--glass-highlight)',
      },
      fontFamily: {
        sans: ['Outfit', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        'lg': '12px',
        'xl': '16px',
        '2xl': '20px',
        '3xl': '24px',
      },
      backgroundImage: {
        'primary-gradient': 'var(--primary-gradient)',
      },
      animation: {
        'float': 'float 8s ease-in-out infinite',
        'float-reverse': 'float 8s ease-in-out infinite reverse',
        'pulse-slow': 'pulse 3s ease-in-out infinite',
        'scale-in': 'scaleIn 0.5s ease-out',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        scaleIn: {
          'from': { opacity: '0', transform: 'scale(0.95)' },
          'to': { opacity: '1', transform: 'scale(1)' },
        }
      }
    },
  },
  plugins: [],
};