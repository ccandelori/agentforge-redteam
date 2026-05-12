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
import { ref, onMounted } from "vue";

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
