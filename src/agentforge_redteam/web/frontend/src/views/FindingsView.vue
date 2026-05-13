<script setup>
import { RouterLink } from "vue-router";
import { api, usePolledResource } from "../composables/api.js";

const { data, loading, error } = usePolledResource(() => api("/findings"));
</script>

<template>
    <h2>Findings</h2>
    <div class="card">
        <p>
            Confirmed vulnerabilities filed by the Documentation Agent.
            P0/P1 and low-confidence verdicts route through
            <RouterLink to="/ui/queue">the approval queue</RouterLink>
            before reaching this table.
        </p>
    </div>

    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="error" class="flash error">{{ error }}</div>
    <div v-else-if="!data?.findings || data.findings.length === 0" class="empty">
        No findings yet.
    </div>
    <table v-else>
        <thead>
            <tr>
                <th>Sev</th>
                <th>Title</th>
                <th>Finding ID</th>
                <th>Created</th>
                <th>GitLab</th>
                <th></th>
            </tr>
        </thead>
        <tbody>
            <tr v-for="f in data.findings" :key="f.finding_id">
                <td><span :class="['badge', f.severity]">{{ f.severity }}</span></td>
                <td>{{ f.title }}</td>
                <td class="id">{{ f.finding_id }}</td>
                <td>{{ f.created_at?.slice(0, 19) }}</td>
                <td>
                    <template v-if="f.gitlab_issue_id">#{{ f.gitlab_issue_id }}</template>
                    <span v-else class="badge pending">unfiled</span>
                </td>
                <td>
                    <RouterLink class="btn secondary" :to="`/ui/findings/${f.finding_id}`">Open</RouterLink>
                </td>
            </tr>
        </tbody>
    </table>
</template>
