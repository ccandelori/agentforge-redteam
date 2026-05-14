/**
 * Vue 3 SPA entry — AgentForge Red Team operator UI.
 *
 * No runtime template compilation (we ship .vue SFCs compiled at build time
 * by @vitejs/plugin-vue), no CDN dependency, no `unsafe-eval` needed in CSP.
 *
 * The JSON API at the root (/coverage, /findings, /queue, /halt, /sessions)
 * is the contract. BasicAuth is enforced at the FastAPI layer; the browser
 * caches credentials per origin and includes them on every XHR.
 */

import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";

import App from "./App.vue";
import "../style.css";

const router = createRouter({
    history: createWebHistory(),
    routes: [
        { path: "/ui",                 name: "session",        component: () => import("./views/SessionView.vue") },
        { path: "/ui/history",         name: "history",        component: () => import("./views/HistoryView.vue") },
        { path: "/ui/coverage",        name: "coverage",       component: () => import("./views/CoverageView.vue") },
        { path: "/ui/findings",        name: "findings",       component: () => import("./views/FindingsView.vue") },
        { path: "/ui/findings/:id",    name: "finding-detail", component: () => import("./views/FindingDetailView.vue"), props: true },
        { path: "/ui/queue",           name: "queue",          component: () => import("./views/QueueView.vue") },
        { path: "/ui/regressions",     name: "regressions",    component: () => import("./views/RegressionsView.vue") },
        { path: "/ui/halt",            name: "halt",           component: () => import("./views/HaltView.vue") },
    ],
});

createApp(App).use(router).mount("#app");
