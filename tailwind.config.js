import { defineConfig } from '@tailwindcss/vite'

export default defineConfig({
  content: ["./templates/**/*.html"],
  theme: {
    extend: {
      colors: {
        cozy: {
          cream: '#faf8f3',
          warmwhite: '#f9f7f2',
          beige: '#f0ede6',
          sand: '#e8e3d8',
          brown: {
            50: '#f9f7f4',
            100: '#f0ede6',
            200: '#e1d9cc',
            300: '#cfc0a8',
            400: '#b8a382',
            500: '#a08966',
            600: '#8b7355',
            700: '#725d47',
            800: '#5d4b3c',
            900: '#4a3d32',
          },
          orange: {
            50: '#fef7ed',
            100: '#fdedd4',
            200: '#fad7a8',
            300: '#f6bb71',
            400: '#f19638',
            500: '#ed7614',
            600: '#de5c0a',
            700: '#b8460b',
            800: '#933710',
            900: '#782f11',
          },
          green: {
            50: '#f0f9f4',
            100: '#dcf2e4',
            200: '#bce4cc',
            300: '#8ecfa7',
            400: '#5ab67c',
            500: '#369b5a',
            600: '#277d46',
            700: '#20643a',
            800: '#1d5030',
            900: '#1a4228',
          },
          gold: {
            50: '#fffdf0',
            100: '#fefce8',
            200: '#fef08a',
            300: '#fde047',
            400: '#facc15',
            500: '#eab308',
            600: '#ca8a04',
            700: '#a16207',
            800: '#854d0e',
            900: '#713f12',
          }
        }
      },
    },
  },
})
