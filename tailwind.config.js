/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        dfir: '#0d1117',
        card: '#161b22',
        cardalt: '#1c2333',
        border: '#30363d',
        primary: '#e6edf3',
        muted: '#8b949e',
        blue: '#58a6ff',
        green: '#3fb950',
        red: '#f85149',
        orange: '#d29922',
        purple: '#bc8cff',
      },
    },
  },
  plugins: [],
};
