/**
 * Thin fetch wrapper + Vue Composition utility for resource loading.
 *
 * - `api(path)` and `apiPost(path, body)` are the only call sites for the
 *   JSON API. Auth is handled by the browser via BasicAuth — credentials
 *   are never embedded here.
 * - `useResource(loader)` is the standard pattern for "load on mount, expose
 *   loading/error/data + a refetch()." Components that need polling or
 *   refetch-after-mutation use refetch().
 */
import { ref, onMounted, onUnmounted } from "vue";

/**
 * Module-level shared ref for the "session started" flash on the
 * SessionView. Lives at module scope so it survives RouterView swaps
 * (the SessionView component unmounts when you navigate to /coverage
 * etc., taking its setup-local refs with it; this one stays).
 *
 * Shape: `{ kind: "ok" | "error", message: string }` or `null`.
 * Caller is responsible for clearing it when no longer relevant.
 */
export const sessionFlash = ref(null);

export async function api(path, init = {}) {
    const resp = await fetch(path, {
        credentials: "same-origin",
        headers: { Accept: "application/json", ...(init.headers || {}) },
        ...init,
    });
    if (!resp.ok) {
        let detail = resp.statusText;
        try { detail = (await resp.json()).detail ?? detail; } catch { /* not JSON */ }
        const err = new Error(`HTTP ${resp.status}: ${detail}`);
        err.status = resp.status;
        throw err;
    }
    if (resp.status === 204) return null;
    return resp.json();
}

export function apiPost(path, body = {}) {
    return api(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
}

export function useResource(loader) {
    const data = ref(null);
    const loading = ref(true);
    const error = ref(null);
    const refetch = async () => {
        loading.value = true;
        error.value = null;
        try {
            data.value = await loader();
        } catch (e) {
            error.value = String(e?.message ?? e);
        } finally {
            loading.value = false;
        }
    };
    onMounted(refetch);
    return { data, loading, error, refetch };
}

/**
 * Polled variant of `useResource` — refetches every `intervalMs` while
 * the component is mounted. Used by the views that watch live sessions
 * (Coverage, Findings, Queue, SessionView). The polling timer is cleared
 * on unmount so navigating away stops the chatter.
 *
 * The first fetch fires on mount (same as `useResource`); subsequent
 * fetches do NOT toggle `loading` so the UI does not blink to "loading…"
 * every few seconds — only the first load shows a spinner.
 */
export function usePolledResource(loader, intervalMs = 3000) {
    const data = ref(null);
    const loading = ref(true);
    const error = ref(null);
    let firstLoadDone = false;

    const refetch = async () => {
        if (!firstLoadDone) loading.value = true;
        try {
            data.value = await loader();
            error.value = null;
        } catch (e) {
            error.value = String(e?.message ?? e);
        } finally {
            if (!firstLoadDone) {
                loading.value = false;
                firstLoadDone = true;
            }
        }
    };

    let timer = null;
    onMounted(() => {
        refetch();
        timer = setInterval(refetch, intervalMs);
    });
    onUnmounted(() => {
        if (timer !== null) clearInterval(timer);
    });

    return { data, loading, error, refetch };
}
