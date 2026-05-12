<script setup>
import { ref } from "vue";
import { apiPost } from "../composables/api.js";

// MVP: no GET /kill_switch endpoint yet. We render in "running" state initially
// and let the first action authoritatively update. A future endpoint should
// expose the current flag so we don't have to guess.
const enabled = ref(false);
const busy = ref(false);
const flash = ref(null);

async function halt() {
    if (!confirm("Trip the kill switch? All agents will halt on their next tool call.")) return;
    busy.value = true;
    flash.value = null;
    try {
        const r = await apiPost("/halt");
        enabled.value = r.status === "halted";
        flash.value = { kind: "ok", message: "Kill switch tripped." };
    } catch (e) {
        flash.value = { kind: "error", message: String(e?.message ?? e) };
    } finally {
        busy.value = false;
    }
}

async function resume() {
    busy.value = true;
    flash.value = null;
    try {
        const r = await apiPost("/resume");
        enabled.value = r.status === "halted";
        flash.value = { kind: "ok", message: "Kill switch cleared." };
    } catch (e) {
        flash.value = { kind: "error", message: String(e?.message ?? e) };
    } finally {
        busy.value = false;
    }
}
</script>

<template>
    <h2>Kill switch</h2>
    <div class="card">
        <p>
            The kill switch is a single-row flag in <code>kill_switch</code>
            on SQLite. The audited tool wrapper checks this flag <strong>before
            every</strong> tool execution. Tripping the switch halts the next
            call from any agent on the next attempt.
        </p>
    </div>

    <div v-if="flash" :class="['flash', flash.kind === 'error' ? 'error' : '']">
        {{ flash.message }}
    </div>

    <div class="halt-block">
        <div class="switch-state">
            Current state:
            <span v-if="enabled" class="state-pill halted">HALTED</span>
            <span v-else class="state-pill running">RUNNING</span>
        </div>

        <template v-if="enabled">
            <p>All agent tool calls are refused. Resume below to allow the platform to continue.</p>
            <button class="btn resume" :disabled="busy"
                    style="font-size: 22px; padding: 18px 36px;"
                    @click="resume">
                {{ busy ? '...' : 'RESUME PLATFORM' }}
            </button>
        </template>
        <template v-else>
            <p>Tripping the switch will refuse the next tool call from every agent on first attempt after the flag flips.</p>
            <button class="btn halt-big" :disabled="busy" @click="halt">
                {{ busy ? '...' : 'HALT PLATFORM' }}
            </button>
        </template>
    </div>

    <div class="card" style="margin-top: 24px;">
        <h3>Operational notes</h3>
        <ul style="margin-left: 20px;">
            <li>The CLI mirror is <code>agentforge-redteam halt</code> / <code>resume</code> / <code>status</code>.</li>
            <li>Halt persists across process restarts (it's a DB flag, not in-memory).</li>
            <li>An operator who resumes accepts that any partially-completed
                work picked up at the previous step is intentional.</li>
        </ul>
    </div>
</template>
