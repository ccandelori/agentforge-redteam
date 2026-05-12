<script setup>
import { api, useResource } from "../composables/api.js";

const { data, loading, error } = useResource(() => api("/coverage"));

function anyFindings(row) {
    return Object.values(row?.findings_by_severity || {}).some(c => c > 0);
}
</script>

<template>
    <h2>Coverage matrix</h2>
    <div class="card">
        <p>
            Per (category, sub_attack), the orchestrator's prioritization input.
            Higher coverage gap and historical-finding severity score push that
            sub_attack up the queue on the next dispatch.
        </p>
    </div>

    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="error" class="flash error">{{ error }}</div>
    <div v-else-if="!data?.rows || data.rows.length === 0" class="empty">
        Coverage matrix is empty. Run a session first.
    </div>
    <table v-else>
        <thead>
            <tr>
                <th>Category</th>
                <th>Sub-attack</th>
                <th>Runs 7d</th>
                <th>Runs lifetime</th>
                <th>Findings</th>
                <th>Avg cost</th>
                <th>Score</th>
                <th>Last run</th>
            </tr>
        </thead>
        <tbody>
            <tr v-for="r in data.rows" :key="`${r.category}:${r.sub_attack}`">
                <td><span class="badge cat">{{ r.category }}</span></td>
                <td><code>{{ r.sub_attack }}</code></td>
                <td>{{ r.runs_last_7d }}</td>
                <td>{{ r.runs_lifetime }}</td>
                <td>
                    <template v-for="(count, sev) in r.findings_by_severity" :key="sev">
                        <span v-if="count > 0" :class="['badge', sev]" style="margin-right: 4px;">
                            {{ sev }}:{{ count }}
                        </span>
                    </template>
                    <span v-if="!anyFindings(r)">—</span>
                </td>
                <td>{{ r.avg_cost_cents }}¢</td>
                <td>{{ Number(r.coverage_score).toFixed(2) }}</td>
                <td>{{ r.last_run_at?.slice(0, 19) || '—' }}</td>
            </tr>
        </tbody>
    </table>
</template>
