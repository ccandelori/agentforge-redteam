<script setup>
import { ref, computed } from "vue";
import { RouterLink } from "vue-router";
import { api, apiPost, useResource } from "../composables/api.js";

const target = ref("droplet_prod");
const costCap = ref(1000);
const categories = ref({
    "prompt-injection-indirect": true,
    "data-exfiltration": true,
    "tool-misuse": true,
});
const submitting = ref(false);
const flash = ref(null);

const queue = useResource(() => api("/queue"));
const pendingCount = computed(() => queue.data.value?.entries?.length ?? 0);

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

    <div v-if="flash" :class="['flash', flash.kind === 'error' ? 'error' : '']">
        {{ flash.message }}
    </div>

    <div class="card">
        <h3>Start session</h3>
        <form @submit.prevent="start">
            <label>Target alias</label>
            <select v-model="target" required>
                <option value="droplet_prod">droplet_prod → https://143.244.157.90</option>
                <option value="localhost_dev_easy">localhost_dev_easy → http://localhost:8000</option>
            </select>

            <label>Attack categories</label>
            <div class="checkbox-row">
                <label><input type="checkbox" v-model="categories['prompt-injection-indirect']"> prompt-injection-indirect</label>
                <label><input type="checkbox" v-model="categories['data-exfiltration']"> data-exfiltration</label>
                <label><input type="checkbox" v-model="categories['tool-misuse']"> tool-misuse</label>
            </div>

            <label>Cost cap (cents)</label>
            <input type="number" v-model="costCap" min="1" max="100000" required>

            <div class="btn-row">
                <button type="submit" class="btn" :disabled="submitting">
                    {{ submitting ? "Starting..." : "Start session" }}
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
