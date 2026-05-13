<script setup>
import { ref } from "vue";
import { api, apiPost, usePolledResource } from "../composables/api.js";

const { data, loading, error, refetch } = usePolledResource(() => api("/queue"));
const busy = ref(null);   // queue_id currently mutating
const flash = ref(null);

async function approve(queueId) {
    busy.value = queueId;
    flash.value = null;
    try {
        const r = await apiPost(`/queue/${queueId}/approve`, { reviewer: "operator" });
        flash.value = { kind: "ok", message: `Approved + filed: #${r.gitlab_issue_id} (${r.gitlab_issue_url})` };
        await refetch();
    } catch (e) {
        flash.value = { kind: "error", message: String(e?.message ?? e) };
    } finally {
        busy.value = null;
    }
}

async function reject(queueId) {
    if (!confirm("Reject this finding? It will be converted to a Judge ground-truth case.")) return;
    busy.value = queueId;
    flash.value = null;
    try {
        await apiPost(`/queue/${queueId}/reject`, {
            reviewer: "operator",
            reason: "rejected via web UI",
            category: "prompt-injection-indirect",
            write_ground_truth: true,
        });
        flash.value = { kind: "ok", message: "Rejected and added to ground-truth." };
        await refetch();
    } catch (e) {
        flash.value = { kind: "error", message: String(e?.message ?? e) };
    } finally {
        busy.value = null;
    }
}
</script>

<template>
    <h2>Approval queue</h2>
    <div class="card">
        <p>
            High-stakes findings (P0/P1) and any verdict with confidence
            below 0.7 land here for operator review.
            <strong>Approve</strong> files an issue (GitLab if configured, else the local
            <code>findings/</code> sink). <strong>Reject</strong> records the rejection
            and, unless you opt out, converts the case into a Judge
            ground-truth canary.
        </p>
    </div>

    <div v-if="flash" :class="['flash', flash.kind === 'error' ? 'error' : '']">
        {{ flash.message }}
    </div>

    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="error" class="flash error">{{ error }}</div>
    <div v-else-if="!data?.entries || data.entries.length === 0" class="empty">
        Queue is empty. The Doc Agent routes findings here when severity is P0/P1
        or confidence &lt; 0.7.
    </div>
    <table v-else>
        <thead>
            <tr>
                <th>Sev</th>
                <th>Title</th>
                <th>Conf</th>
                <th>Queue ID</th>
                <th>Approve</th>
                <th>Reject</th>
            </tr>
        </thead>
        <tbody>
            <tr v-for="e in data.entries" :key="e.queue_id">
                <td><span :class="['badge', e.severity]">{{ e.severity }}</span></td>
                <td>{{ e.title }}</td>
                <td>{{ Number(e.confidence).toFixed(2) }}</td>
                <td class="id">{{ e.queue_id }}</td>
                <td>
                    <button class="btn approve" :disabled="busy === e.queue_id" @click="approve(e.queue_id)">
                        {{ busy === e.queue_id ? '...' : 'Approve' }}
                    </button>
                </td>
                <td>
                    <button class="btn reject" :disabled="busy === e.queue_id" @click="reject(e.queue_id)">
                        {{ busy === e.queue_id ? '...' : 'Reject' }}
                    </button>
                </td>
            </tr>
        </tbody>
    </table>
</template>
