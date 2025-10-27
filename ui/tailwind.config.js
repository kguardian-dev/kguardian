/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'hubble-dark': '#0E1726',
        'hubble-darker': '#0A0F1C',
        'hubble-card': '#1A2332',
        'hubble-border': '#2A3647',
        'hubble-accent': '#3B82F6',
        'hubble-success': '#10B981',
        'hubble-warning': '#F59E0B',
        'hubble-error': '#EF4444',
      },
    },
  },
  plugins: [],
}
