<script setup>
import { ref, computed } from "vue";
import { RouterLink } from "vue-router";
import {
    api,
    apiPost,
    categorySelections,
    sessionFlash,
    usePolledResource,
} from "../composables/api.js";

const target = ref("droplet_prod");
const costCap = ref(25);
// All 6 threat-model categories (THREAT_MODEL.md Table 1). The ref lives
// at module scope (composables/api.js) so the operator's checkbox
// selections survive navigating away from SessionView and back —
// SessionView is unmounted by Vue Router on navigation, and a
// setup-local ref would reinitialize to defaults on remount.
const categories = categorySelections;
const submitting = ref(false);
// `flash` is the module-level shared ref so the "Session started: …"
// banner survives navigation away from this view and back. The
// SessionView component remounts on each visit; setup-local refs would
// reset to null. See composables/api.js for the ref definition.
const flash = sessionFlash;

const queue = usePolledResource(() => api("/queue"));
const pendingCount = computed(() => queue.data.value?.entries?.length ?? 0);

// Server-side dispatch tracker: polls /sessions/active so the operator can
// see whether any session is currently in flight. The endpoint snapshot is
// in-memory and per-uvicorn-worker, which is fine for the single-worker
// MVP — restart wipes it to "idle".
const activeSessions = usePolledResource(() => api("/sessions/active"));
const isRunning = computed(() => activeSessions.data.value?.is_running ?? false);
const activeCount = computed(() => activeSessions.data.value?.count ?? 0);
const activity = computed(() => activeSessions.data.value?.activity ?? []);

// Human-friendly relative-time for the "last step at" stamp. Re-evaluates
// every poll tick because activity is a polled resource — no need for a
// separate timer.
function relativeAgo(iso) {
    if (!iso) return "—";
    const then = new Date(iso).getTime();
    const seconds = Math.max(0, Math.floor((Date.now() - then) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    return `${Math.floor(seconds / 3600)}h ago`;
}

async function start() {
    submitting.value = true;
    flash.value = null;
    try {
        const selected = Object.entries(categories.value).filter(([, v]) => v).map(([k]) => k);
        if (selected.length === 0) throw new Error("Pick at least one category.");
        const r = await apiPost("/sessions/start", {
            target: target.value,
            cost_cap_cents: Number(costCap.value),
            categories: selected,
        });
        flash.value = { kind: "ok", message: `Session started: ${r.session_id}` };
        // Surface the running-state immediately rather than waiting for the
        // next poll tick. The bg task lands on the threadpool ~10ms after
        // POST returns; an immediate refetch confirms the operator's click.
        activeSessions.refetch();
        queue.refetch();
    } catch (e) {
        flash.value = { kind: "error", message: String(e?.message ?? e) };
    } finally {
        submitting.value = false;
    }
}
</script>

<template>
    <h2>Kick off a session</h2>

    <div class="card">
        <p>
            Each session is one orchestrator-led run against the configured target.
            The platform halts on kill-switch, budget exhaustion, regression-due
            target SHA, or 5 consecutive fail verdicts (no-progress).
        </p>
    </div>

    <!-- Live-activity panel for any in-flight session(s). Visible only while
         the server reports a dispatch is running. Re-renders every 3s as the
         polled resource ticks; this is the operator's reassurance signal that
         the platform is doing work, even on a session that produces zero
         findings (the Co-Pilot defending all attacks is a legitimate
         "well-built target" outcome — but visually identical to "idle"
         without these counters). -->
    <div v-if="isRunning && activity.length > 0" class="card live-activity">
        <h3>Live activity</h3>
        <div v-for="a in activity" :key="a.session_id" class="activity-row">
            <div class="activity-id"><code>{{ a.session_id.slice(0, 8) }}…</code></div>
            <div class="activity-grid">
                <div class="stat-mini">
                    <div class="label">attacks</div>
                    <div class="value">{{ a.attacks }}</div>
                </div>
                <div class="stat-mini">
                    <div class="label">verdicts</div>
                    <div class="value">{{ a.verdicts }}</div>
                </div>
                <div class="stat-mini stat-pass">
                    <div class="label">pass</div>
                    <div class="value">{{ a.verdicts_pass }}</div>
                </div>
                <div class="stat-mini stat-partial">
                    <div class="label">partial</div>
                    <div class="value">{{ a.verdicts_partial }}</div>
                </div>
                <div class="stat-mini stat-fail">
                    <div class="label">fail</div>
                    <div class="value">{{ a.verdicts_fail }}</div>
                </div>
                <div class="stat-mini">
                    <div class="label">findings</div>
                    <div class="value">{{ a.findings }}</div>
                </div>
                <div class="stat-mini">
                    <div class="label">cost</div>
                    <div class="value">${{ (a.cost_cents / 100).toFixed(2) }}</div>
                </div>
            </div>
            <div v-if="a.last_agent" class="activity-last">
                last step: <strong>{{ a.last_agent }}</strong> · <code>{{ a.last_tool }}</code>
                <span class="dim"> ({{ relativeAgo(a.last_step_at) }})</span>
            </div>
        </div>
    </div>

    <div v-if="flash" :class="['flash', flash.kind === 'error' ? 'error' : '']">
        <div>{{ flash.message }}</div>
        <div v-if="flash.kind === 'ok'" style="margin-top: 8px; font-size: 14px;">
            Session is running in the background. Watch live:
            <RouterLink to="/ui/coverage">Coverage</RouterLink> ·
            <RouterLink to="/ui/findings">Findings</RouterLink> ·
            <RouterLink to="/ui/queue">Queue</RouterLink>
            (each page auto-refreshes every 3 seconds.)
        </div>
    </div>

    <div class="card">
        <h3>
            Start session
            <span class="status-badge" :class="{ running: isRunning, idle: !isRunning }">
                <span v-if="isRunning">● Running ({{ activeCount }})</span>
                <span v-else>○ Idle</span>
            </span>
        </h3>
        <form @submit.prevent="start">
            <label>Target alias</label>
            <select v-model="target" required>
                <option value="droplet_prod">droplet_prod → https://143.244.157.90:9300</option>
                <option value="localhost_dev_easy">localhost_dev_easy → http://localhost:8000</option>
            </select>

            <label>Attack categories</label>
            <div class="checkbox-row">
                <label><input type="checkbox" v-model="categories['prompt-injection-indirect']"> prompt-injection-indirect</label>
                <label><input type="checkbox" v-model="categories['data-exfiltration']"> data-exfiltration</label>
                <label><input type="checkbox" v-model="categories['tool-misuse']"> tool-misuse</label>
                <label><input type="checkbox" v-model="categories['state-corruption']"> state-corruption</label>
                <label><input type="checkbox" v-model="categories['dos-cost-amplification']"> dos-cost-amplification</label>
                <label><input type="checkbox" v-model="categories['identity-role-exploitation']"> identity-role-exploitation</label>
            </div>

            <label>Cost cap (cents)</label>
            <input type="number" v-model="costCap" min="1" max="100000" required>

            <div class="btn-row">
                <button type="submit" class="btn" :disabled="submitting || isRunning">
                    {{ submitting ? "Starting..." : (isRunning ? "Session in flight..." : "Start session") }}
                </button>
                <RouterLink class="btn secondary" to="/ui/coverage">View coverage matrix</RouterLink>
            </div>
        </form>
    </div>

    <div class="grid-2">
        <div class="stat">
            <div class="label">Pending in queue</div>
            <div class="value">
                <span v-if="queue.loading.value">…</span>
                <span v-else-if="queue.error.value" style="color: var(--red)">error</span>
                <span v-else>{{ pendingCount }}</span>
            </div>
        </div>
        <div class="stat">
            <div class="label">API surface</div>
            <div class="value" style="font-size: 14px; padding-top: 8px;">
                <code>POST /sessions/start</code><br>
                <code>GET&nbsp; /coverage</code><br>
                <code>GET&nbsp; /findings</code>
            </div>
        </div>
    </div>
</template>
