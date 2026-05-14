<script setup>
import { ref } from "vue";
import { api, usePolledResource } from "../composables/api.js";

const { data, loading, error } = usePolledResource(() => api("/regressions"));

// Per-row drill-down: track which run_ids are expanded.
const expanded = ref(new Set());
function toggle(runId) {
    if (expanded.value.has(runId)) {
        expanded.value.delete(runId);
    } else {
        expanded.value.add(runId);
    }
    expanded.value = new Set(expanded.value); // force reactivity
}
function statusClass(status) {
    return {
        held: "cat",
        regressed: "P0",
        weakly_passing: "P2",
        inconclusive: "P3",
    }[status] || "pending";
}
</script>

<template>
    <h2>Regression replays</h2>
    <div class="card">
        <p>
            Every replay of a promoted finding (from
            <code>evals/regressions/</code>) against a target SHA. The
            harness re-judges with the original rubric and compares to the
            promoted verdict — if the new verdict matches, the case
            <em>held</em>; if it diverges, the case
            <em>regressed</em>. Run via
            <code>agentforge-redteam regress</code> or automatically when
            the orchestrator halts on <code>regression_due</code>.
        </p>
    </div>

    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="error" class="flash error">{{ error }}</div>
    <div v-else-if="!data?.runs || data.runs.length === 0" class="empty">
        No regression replays yet. Promote a finding to
        <code>evals/regressions/</code> and run
        <code>agentforge-redteam regress</code>.
    </div>
    <table v-else>
        <thead>
            <tr>
                <th>Status</th>
                <th>Finding ID</th>
                <th>Target SHA</th>
                <th>Replayed</th>
                <th></th>
            </tr>
        </thead>
        <tbody>
            <template v-for="r in data.runs" :key="r.run_id">
                <tr>
                    <td>
                        <span :class="['badge', statusClass(r.status)]">{{ r.status }}</span>
                    </td>
                    <td class="id" :title="r.finding_id">{{ r.finding_id.slice(0, 8) }}…</td>
                    <td><code>{{ r.target_sha.slice(0, 16) }}{{ r.target_sha.length > 16 ? '…' : '' }}</code></td>
                    <td>{{ r.created_at?.slice(0, 19) }}</td>
                    <td>
                        <button class="btn secondary" @click="toggle(r.run_id)">
                            {{ expanded.has(r.run_id) ? 'Hide' : 'Detail' }}
                        </button>
                    </td>
                </tr>
                <tr v-if="expanded.has(r.run_id)">
                    <td colspan="5">
                        <pre style="background: var(--ink); color: var(--paper); padding: 12px; overflow-x: auto;">{{ JSON.stringify(r.raw, null, 2) }}</pre>
                    </td>
                </tr>
            </template>
        </tbody>
    </table>
</template>
