<script setup>
import { api, usePolledResource } from "../composables/api.js";

const { data, loading, error } = usePolledResource(() => api("/sessions"));

function inflightLabel(s) {
    return s.halt_reason === null ? "in flight" : s.halt_reason;
}
function dollars(cents) {
    return (cents / 100).toFixed(2);
}
function durationMin(s) {
    if (!s.ended_at) return "—";
    const start = Date.parse(s.started_at);
    const end = Date.parse(s.ended_at);
    if (isNaN(start) || isNaN(end)) return "—";
    return ((end - start) / 60000).toFixed(1) + "m";
}
function capPct(s) {
    if (!s.cost_cap_cents) return 0;
    return Math.min(100, Math.round(100 * s.cost_so_far_cents / s.cost_cap_cents));
}
</script>

<template>
    <h2>History</h2>
    <div class="card">
        <p>
            Every session ever dispatched on this platform, newest first.
            ``halt_reason`` and ``ended_at`` are populated by the dispatcher
            on terminal exit (commit
            <code>227753d</code>); in-flight sessions show <em>in flight</em>.
            Cost vs cap shows what the operator's $X.XX cap actually
            consumed — the cost-cap leakage fix (commit <code>d73f2bc</code>)
            keeps the bar honest.
        </p>
    </div>

    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="error" class="flash error">{{ error }}</div>
    <div v-else-if="!data?.sessions || data.sessions.length === 0" class="empty">
        No sessions yet. Trigger one from the
        <RouterLink to="/ui">Session</RouterLink>
        page.
    </div>
    <table v-else>
        <thead>
            <tr>
                <th>Session ID</th>
                <th>Started</th>
                <th>Halt reason</th>
                <th>Duration</th>
                <th>Campaigns</th>
                <th>Cost</th>
                <th>Cap</th>
                <th>% used</th>
            </tr>
        </thead>
        <tbody>
            <tr v-for="s in data.sessions" :key="s.session_id">
                <td class="id" :title="s.session_id">{{ s.session_id.slice(0, 8) }}…</td>
                <td>{{ s.started_at?.slice(0, 19) }}</td>
                <td>
                    <span v-if="s.halt_reason === null" class="badge pending">in flight</span>
                    <span v-else-if="s.halt_reason === 'completed' || s.halt_reason === 'no_progress'"
                          class="badge cat">{{ s.halt_reason }}</span>
                    <span v-else-if="s.halt_reason === 'budget_exhausted'"
                          class="badge P2">{{ s.halt_reason }}</span>
                    <span v-else-if="s.halt_reason.startsWith('dispatcher_')"
                          class="badge P1">{{ s.halt_reason }}</span>
                    <span v-else class="badge P0">{{ s.halt_reason }}</span>
                </td>
                <td>{{ durationMin(s) }}</td>
                <td>{{ s.campaigns_run }}</td>
                <td>${{ dollars(s.cost_so_far_cents) }}</td>
                <td>${{ dollars(s.cost_cap_cents) }}</td>
                <td>
                    <span :class="['badge', capPct(s) > 90 ? 'P1' : capPct(s) > 70 ? 'P2' : 'cat']">
                        {{ capPct(s) }}%
                    </span>
                </td>
            </tr>
        </tbody>
    </table>
</template>
