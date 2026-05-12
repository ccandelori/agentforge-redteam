<script setup>
import { RouterLink } from "vue-router";
import { api, useResource } from "../composables/api.js";

const props = defineProps({ id: { type: String, required: true } });
const { data, loading, error } = useResource(() => api(`/findings/${props.id}`));
</script>

<template>
    <div v-if="loading" class="empty">Loading…</div>
    <div v-else-if="error" class="flash error">{{ error }}</div>
    <template v-else-if="data">
        <h2>
            <span :class="['badge', data.severity]">{{ data.severity }}</span>
            Finding
        </h2>

        <div class="card">
            <p><strong>Finding ID:</strong> <code>{{ data.finding_id }}</code></p>
            <p><strong>Title:</strong> {{ data.title }}</p>
            <p><strong>Created:</strong> {{ data.created_at?.slice(0, 19) }}</p>
            <p>
                <strong>GitLab issue:</strong>
                <template v-if="data.gitlab_issue_id">#{{ data.gitlab_issue_id }}</template>
                <span v-else class="badge pending">unfiled</span>
            </p>
            <RouterLink class="btn secondary" to="/ui/findings">&larr; Back to findings</RouterLink>
        </div>

        <h3>Attack payload</h3>
        <pre>{{ data.attack_payload }}</pre>

        <h3>Target response</h3>
        <pre>{{ data.target_response }}</pre>

        <template v-if="data.rendered_markdown">
            <h3>Rendered report</h3>
            <div class="finding-md" v-html="data.rendered_markdown"></div>
        </template>
        <div v-else class="empty">No rendered report yet for this finding.</div>
    </template>
</template>
