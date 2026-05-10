/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                cyber: {
                    void: '#09090b',
                    cyan: '#00f3ff',
                    pink: '#ff003c',
                    green: '#39ff14',
                    amber: '#ffb000'
                }
            },
            fontFamily: {
                sans: ['"Orbitron"', 'sans-serif'],
                mono: ['"Share Tech Mono"', '"JetBrains Mono"', 'monospace'],
            }
        },
    },
    plugins: [],
}
