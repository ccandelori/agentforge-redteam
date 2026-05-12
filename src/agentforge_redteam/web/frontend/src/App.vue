<script setup>
import { RouterLink, RouterView } from "vue-router";

const version = "0.1.0";
</script>

<template>
    <header class="brand">
        <h1>AgentForge.RedTeam</h1>
        <span class="tag">v{{ version }}</span>
        <span class="tag" style="background: var(--accent); color: var(--paper);">OPERATOR</span>
    </header>

    <nav class="side">
        <RouterLink to="/ui">SESSION</RouterLink>
        <RouterLink to="/ui/coverage">COVERAGE</RouterLink>
        <RouterLink to="/ui/findings">FINDINGS</RouterLink>
        <RouterLink to="/ui/queue">QUEUE</RouterLink>
        <RouterLink to="/ui/halt" class="danger">HALT</RouterLink>
    </nav>

    <main>
        <RouterView />
    </main>
</template>
