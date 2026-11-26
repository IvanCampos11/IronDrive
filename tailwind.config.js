/** @type {import('tailwindcss').Config} */

// Colors are CSS variables (see static/css/input.css) so light/dark themes are
// a single variable swap instead of `dark:` variants on every element.
const v = (name) => `rgb(var(--c-${name}) / <alpha-value>)`;

module.exports = {
  content: ["./templates/**/*.tera", "./static/js/**/*.js"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: v("bg"),
        surface: v("surface"),
        "surface-2": v("surface-2"),
        "surface-3": v("surface-3"),
        fg: v("fg"),
        muted: v("muted"),
        subtle: v("subtle"),
        outline: v("outline"),
        primary: v("primary"),
        "on-primary": v("on-primary"),
        "primary-container": v("primary-container"),
        "on-primary-container": v("on-primary-container"),
        danger: v("danger"),
        "danger-container": v("danger-container"),
        "on-danger-container": v("on-danger-container"),
        success: v("success"),
        warning: v("warning"),
        inverse: v("inverse"),
        "on-inverse": v("on-inverse"),
      },
      fontFamily: {
        sans: ["Roboto", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        1: "0 1px 2px 0 rgb(0 0 0 / 0.12), 0 1px 3px 1px rgb(0 0 0 / 0.06)",
        2: "0 1px 2px 0 rgb(0 0 0 / 0.15), 0 2px 6px 2px rgb(0 0 0 / 0.08)",
        3: "0 4px 8px 3px rgb(0 0 0 / 0.10), 0 1px 3px 0 rgb(0 0 0 / 0.15)",
      },
      borderRadius: {
        "4xl": "1.75rem",
      },
    },
  },
  plugins: [],
};
