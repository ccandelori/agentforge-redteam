/**
 * Vite config — AgentForge Red Team operator UI.
 *
 * The SPA is served at /ui/ on the FastAPI app (web/app.py:spa()). Vite's
 * `base` option makes every emitted asset reference (in index.html and the
 * built JS chunks) absolute under /ui/ so the FastAPI catch-all serves them
 * back correctly. Without this, references would be /assets/... and 404.
 *
 * Build output lands in `dist/` (gitignored). `web/app.py` serves files
 * from this dir; the deploy rsync ships the built artifacts.
 */
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
    base: "/ui/",
    plugins: [vue()],
    build: {
        outDir: "dist",
        emptyOutDir: true,
        // Source maps so 4xx/5xx error traces from the SPA point at the
        // original .vue files. Not large for our component count.
        sourcemap: true,
    },
    server: {
        // `npm run dev` proxy: any non-/ui request (the JSON API) gets
        // forwarded to the FastAPI dev server on 8080 so the SPA's
        // fetch('/coverage') etc. works locally without CORS.
        port: 5173,
        proxy: {
            "^/(coverage|findings|queue|halt|resume|sessions|healthz)(/|$)": {
                target: "http://127.0.0.1:8080",
                changeOrigin: true,
            },
        },
    },
});
