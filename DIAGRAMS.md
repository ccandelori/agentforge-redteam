# Diagrams — AgentForge Adversarial AI Security Platform

**Date**: 2026-05-11
**Companion to**: `ARCHITECTURE.md`. The agent-interaction overview lives there; this document covers the complementary views — system context, sequence, data flow, state store, regression, decision tree, trust boundaries, HITL.

All diagrams are Mermaid (renders in GitLab / GitHub markdown previews and most IDEs). For text-only viewing, ASCII fallbacks are included where the visual matters.

---

## 1. System Context (C4 Level 1)

Where the platform sits in its environment. Shows external actors and external systems the platform integrates with — without revealing internal structure.

```mermaid
graph TB
    classDef person fill:#08427B,stroke:#052E56,color:#fff
    classDef system fill:#1168BD,stroke:#0B4884,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff
    classDef target fill:#B22,stroke:#700,color:#fff

    SecEng["Healthcare AI Security Engineer<br/>Primary operator"]:::person
    CISO["Hospital CISO<br/>Accountable owner"]:::person
    DevTeam["AgentForge Product Team<br/>Consumes findings"]:::person

    Platform["AgentForge Adversarial<br/>AI Security Platform<br/>(this system)"]:::system

    Target["AgentForge Clinical Co-Pilot<br/>https://143.244.157.90<br/>(target under test)"]:::target

    Anthropic["Anthropic API<br/>Claude Sonnet, Haiku"]:::external
    OpenAI["OpenAI API<br/>GPT-4o"]:::external
    Langfuse["Langfuse SaaS<br/>Observability"]:::external
    GitLab["GitLab<br/>labs.gauntletai.com<br/>Issue tracker"]:::external

    SecEng -->|configures, triages findings| Platform
    CISO -->|reviews dashboards, audits| Platform
    DevTeam -->|consumes vuln reports| GitLab

    Platform -->|HTTP attacks| Target
    Platform -->|LLM calls (Judge, Doc, Orch)| Anthropic
    Platform -->|LLM calls (Red Team)| OpenAI
    Platform -->|trace export| Langfuse
    Platform -->|file vulnerability issues| GitLab
```

---

## 2. Container View (C4 Level 2)

Internal containers of the platform. Each box is a process / file / store that runs or persists on the platform host.

```mermaid
graph TB
    classDef cli fill:#2E7D32,stroke:#1B5E20,color:#fff
    classDef ui fill:#388E3C,stroke:#2E7D32,color:#fff
    classDef proc fill:#1168BD,stroke:#0B4884,color:#fff
    classDef store fill:#7B5B33,stroke:#5A4327,color:#fff
    classDef cfg fill:#F57F17,stroke:#E65100,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff

    CLI["agentforge-redteam CLI<br/>(Typer)<br/>operator entrypoint"]:::cli
    UI["FastAPI Web UI<br/>(Final only)<br/>:8000"]:::ui

    Graph["LangGraph State Machine<br/>(Python process)<br/>4 agent nodes + audit wrapper"]:::proc
    Reg["Regression Harness<br/>(Python module)"]:::proc
    Cron["GitLab CI Cron<br/>nightly trigger"]:::external

    SQLite[("SQLite<br/>var/platform.db<br/>state + audit + queue + kill switch")]:::store
    Findings[("findings/<br/>local markdown reports")]:::store
    Evals[("evals/regressions/<br/>deterministic test cases")]:::store

    Targets[("targets.yaml<br/>allowlist")]:::cfg
    Rubrics[("rubrics/*.yaml<br/>versioned per category")]:::cfg
    AttackLib[("attack_library.json<br/>seed cases")]:::cfg
    Prompts[("prompts/*.md<br/>agent system prompts")]:::cfg
    Policy[("orchestrator_policy.yaml<br/>doc_policy.yaml")]:::cfg

    Anthropic["Anthropic API"]:::external
    OpenAI["OpenAI API"]:::external
    Langfuse["Langfuse"]:::external
    GitLabAPI["GitLab API"]:::external
    Target["AgentForge Target"]:::external

    CLI --> Graph
    UI --> Graph
    Cron --> CLI

    Graph -->|reads/writes| SQLite
    Graph -->|reads| Targets
    Graph -->|reads| Rubrics
    Graph -->|reads| AttackLib
    Graph -->|reads| Prompts
    Graph -->|reads| Policy
    Graph -->|writes| Findings
    Graph -->|writes| Evals

    Graph -->|Judge, Doc, Orch| Anthropic
    Graph -->|Red Team| OpenAI
    Graph -->|all agents trace| Langfuse
    Graph -->|file issues| GitLabAPI
    Graph -->|attack| Target

    Reg -->|reads| Evals
    Reg -->|replays| Target
    Reg -->|writes results| SQLite

    UI -->|reads| SQLite
    CLI -->|reads| SQLite
```

---

## 3. Single Campaign Sequence

Temporal flow of one attack campaign — Orchestrator dispatches → Red Team attacks → Judge evaluates → Documentation files (or queues). This is the platform's inner loop.

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator
    participant Orch as Orchestrator
    participant SQL as SQLite State
    participant RT as Red Team Agent
    participant Tgt as AgentForge Target
    participant J as Judge Agent
    participant LF as Langfuse
    participant Doc as Documentation Agent
    participant Q as Approval Queue
    participant GL as GitLab

    Op->>Orch: start session (cost cap, max duration)
    Orch->>SQL: read coverage_matrix, open_findings, cost
    Orch->>SQL: check kill_switch
    Orch->>Orch: select_next_campaign()
    Orch->>SQL: write campaign_dispatched
    Orch->>RT: dispatch CampaignBrief

    RT->>SQL: lookup_attack_library(category, sub_attack)
    RT->>RT: construct payload (LLM)
    RT->>SQL: check kill_switch
    RT->>Tgt: HTTP POST /api/agent/turn (attack payload)
    Tgt-->>RT: response (status, body)
    RT->>LF: span(attack record)
    RT->>SQL: append agent_step
    RT->>J: hand off AttackRecord (no Red Team reasoning)

    J->>SQL: load rubric for category
    J->>J: deterministic pre-checks (regex, citation lookup)
    J->>J: LLM rubric fill (Claude Sonnet)
    J->>SQL: write verdict
    J->>LF: span(verdict)

    alt verdict = pass or partial with high confidence
        J->>Doc: ConfirmedFinding
        Doc->>Doc: dedup check (sub_attack + target_sha)
        Doc->>Doc: assign_severity() [deterministic]
        Doc->>Doc: sanitize_evidence() [deterministic]
        Doc->>Doc: write_report() [LLM]
        Doc->>SQL: write finding row

        alt severity in {P0, P1} OR confidence = low
            Doc->>Q: queue for human approval
            Note over Q,Op: operator approves/rejects out-of-band
            Op->>Q: approve
            Q->>GL: create issue
            GL-->>Q: issue_id
        else severity in {P2, P3} AND confidence = high
            Doc->>GL: create issue (autonomous)
            GL-->>Doc: issue_id
        end
    else verdict = fail or inconclusive
        Note over J: no finding, no Doc invocation
    end

    Orch->>SQL: update coverage_matrix
    Orch->>SQL: write campaign_completed
    Orch->>Orch: check budget, canaries, kill_switch
    
    alt should continue
        Orch->>Orch: select_next_campaign() (loop)
    else halt
        Orch->>SQL: write session_halted (reason)
        Orch->>Op: session complete
    end
```

### ASCII fallback (sequence digest)

```
Operator → Orchestrator: start session
  Orchestrator → SQLite: read state, check kill switch
  Orchestrator → Red Team: dispatch campaign
    Red Team → SQLite: lookup attack library
    Red Team → Target: HTTP attack
    Target → Red Team: response
    Red Team → Judge: AttackRecord (no Red Team reasoning)
      Judge → SQLite: load rubric
      Judge → Judge: deterministic + LLM rubric checks
      Judge → SQLite: write verdict
      Judge → Documentation: ConfirmedFinding (if pass/partial)
        Documentation → Doc: dedup, severity, sanitize, draft
        Documentation → SQLite: write finding
        Documentation → Approval Queue OR GitLab: route by severity/confidence
  Orchestrator → SQLite: update coverage matrix
  Orchestrator → Orchestrator: loop or halt
Operator ← Orchestrator: session complete
```

---

## 4. Data Flow Diagram

How attack data flows through the system, from input to filed finding. This is the *what data moves where* view.

```mermaid
flowchart LR
    classDef input fill:#FFEB3B,stroke:#F57F17,color:#000
    classDef agent fill:#1168BD,stroke:#0B4884,color:#fff
    classDef store fill:#7B5B33,stroke:#5A4327,color:#fff
    classDef output fill:#43A047,stroke:#2E7D32,color:#fff
    classDef external fill:#999,stroke:#666,color:#fff

    Seed["Seed payload<br/>(from attack_library.json)"]:::input
    Prior["Prior partially-successful<br/>attacks (from SQLite)"]:::input
    Rubric["Rubric YAML<br/>(versioned)"]:::input

    RT["Red Team<br/>generates / mutates"]:::agent

    Payload["Final attack payload<br/>+ metadata"]:::output

    Tgt["AgentForge Target"]:::external

    Response["Target response<br/>(status, body, latency)"]:::output

    AR["AttackRecord<br/>{payload, response,<br/>target_sha, model, ts, cost}"]:::output

    J["Judge<br/>deterministic checks +<br/>LLM rubric fill"]:::agent

    VR["VerdictRecord<br/>{verdict, confidence,<br/>rubric_sha, evidence}"]:::output

    CF["ConfirmedFinding<br/>{AttackRecord +<br/>VerdictRecord +<br/>severity_input}"]:::output

    Doc["Documentation<br/>severity + sanitize + draft"]:::agent

    Report["VulnerabilityReport<br/>(Markdown)"]:::output

    SQL["SQLite<br/>state store<br/>audit log<br/>coverage matrix"]:::store

    LF["Langfuse<br/>traces"]:::store

    Q["Approval Queue"]:::store

    GL["GitLab Issue"]:::output

    LocalMD["findings/&lt;id&gt;.md<br/>(local)"]:::output

    EvalCase["evals/regressions/<br/>&lt;id&gt;.json"]:::output

    Seed --> RT
    Prior --> RT
    RT --> Payload
    Payload --> Tgt
    Tgt --> Response
    Payload --> AR
    Response --> AR

    AR --> J
    Rubric --> J
    J --> VR

    VR --> CF
    AR --> CF
    CF --> Doc

    Doc --> Report
    Report --> LocalMD
    Report --> Q
    Q --> GL
    Report --> GL
    Report --> EvalCase

    AR -.-> SQL
    AR -.-> LF
    VR -.-> SQL
    VR -.-> LF
    CF -.-> SQL
    Report -.-> SQL
    Report -.-> LF
```

---

## 5. SQLite State Store — Entity Relationship

The tables and their relationships. This is the schema the Orchestrator queries on every dispatch decision.

```mermaid
erDiagram
    run_manifests ||--o{ campaigns : "produces"
    campaigns ||--o{ attacks : "generates"
    attacks ||--|| verdicts : "evaluated by"
    verdicts ||--o| findings : "may produce"
    findings ||--o{ regression_runs : "validated against"
    findings ||--o| human_approval_queue : "may be queued in"
    agent_steps }o--|| attacks : "audits"
    agent_steps }o--|| verdicts : "audits"
    agent_steps }o--|| findings : "audits"
    coverage_matrix ||--o{ campaigns : "informs selection"
    kill_switch ||--|| run_manifests : "halts"
    
    run_manifests {
        uuid session_id PK
        string target_sha
        string rubric_set_sha
        string prompt_set_sha
        timestamp started_at
        timestamp ended_at
        string operator
        decimal cost_total
        string halt_reason
    }
    
    campaigns {
        uuid campaign_id PK
        uuid session_id FK
        string category
        string sub_attack
        decimal cost_budget
        decimal cost_actual
        timestamp dispatched_at
        timestamp completed_at
        string outcome
    }
    
    attacks {
        uuid attack_id PK
        uuid campaign_id FK
        text payload_hash
        text payload
        text target_response
        string target_sha
        string red_team_model
        decimal cost
        timestamp created_at
    }
    
    verdicts {
        uuid verdict_id PK
        uuid attack_id FK
        string verdict
        string confidence
        string rubric_sha
        string judge_model
        json evidence_refs
        json canary_results
        decimal cost
        timestamp created_at
    }
    
    findings {
        uuid finding_id PK
        uuid verdict_id FK
        string severity
        string status
        string sub_attack
        string target_sha_filed
        string gitlab_issue_url
        timestamp filed_at
        timestamp last_validated_at
    }
    
    regression_runs {
        uuid run_id PK
        uuid finding_id FK
        string new_target_sha
        string new_verdict
        boolean regression_detected
        timestamp ran_at
    }
    
    human_approval_queue {
        uuid queue_id PK
        uuid finding_id FK
        string status
        string operator_decision
        timestamp queued_at
        timestamp decided_at
    }
    
    agent_steps {
        uuid step_id PK
        string agent
        string tool
        json args
        json result
        decimal cost
        decimal latency_ms
        string error
        timestamp ts_start
        timestamp ts_end
    }
    
    coverage_matrix {
        string category PK
        string sub_attack PK
        int runs_last_7d
        int runs_lifetime
        json findings_by_severity
        timestamp last_run_at
        timestamp last_regression_at
        decimal avg_cost_per_run_usd
        float coverage_score
    }
    
    kill_switch {
        int id PK
        boolean tripped
        string reason
        string tripped_by
        timestamp tripped_at
    }
```

---

## 6. Regression Harness Flow

How a confirmed finding becomes a deterministic regression test and re-runs against new target builds.

```mermaid
flowchart TB
    classDef event fill:#FFEB3B,stroke:#F57F17,color:#000
    classDef proc fill:#1168BD,stroke:#0B4884,color:#fff
    classDef decision fill:#9C27B0,stroke:#6A1B9A,color:#fff
    classDef outcome fill:#43A047,stroke:#2E7D32,color:#fff
    classDef alert fill:#D32F2F,stroke:#B71C1C,color:#fff

    Find[Finding filed by Doc Agent]:::event
    Promote[Promote to evals/regressions/&lt;id&gt;.json<br/>payload, expected_safe_behavior, judge_check_ids]:::proc

    Trigger{Regression trigger fires}:::decision
    NewSHA[New AgentForge target SHA detected]:::event
    Manual[Operator: agentforge-redteam regress]:::event
    Aged[Finding age > validation_window<br/>and last regression > 30d]:::event

    Iterate[For each finding in evals/regressions/]:::proc
    Replay[Replay payload against new target]:::proc
    Judge[Judge runs ORIGINAL rubric<br/>not latest rubric]:::proc
    Compare{Compare verdicts}:::decision

    Held[Fix held: mark finding 'resolved on target_sha']:::outcome
    Regress[REGRESSION DETECTED]:::alert
    Uncertain[Verdict changed weakly: queue for human]:::alert

    Find --> Promote
    Promote --> Trigger
    NewSHA --> Trigger
    Manual --> Trigger
    Aged --> Trigger
    Trigger --> Iterate
    Iterate --> Replay
    Replay --> Judge
    Judge --> Compare
    Compare -->|fail/inconclusive on safe response| Held
    Compare -->|pass on supposedly-fixed| Regress
    Compare -->|partial/changed type| Uncertain
    Regress -->|"P0/P1: page operator immediately"| Alert[Operator alert]:::alert
```

### Why the ORIGINAL rubric, not the latest

If the rubric itself was updated between filing and regression, a "passes" verdict could mean either (a) the vulnerability was fixed, or (b) the new rubric is more permissive. Using the original rubric makes the regression result *attributable* to the target change, not the platform's evolution.

---

## 7. Orchestrator Decision Tree

How the Orchestrator picks the next campaign. This is the same logic described in `ARCHITECTURE.md`, visualized.

```mermaid
flowchart TB
    classDef check fill:#9C27B0,stroke:#6A1B9A,color:#fff
    classDef halt fill:#D32F2F,stroke:#B71C1C,color:#fff
    classDef select fill:#43A047,stroke:#2E7D32,color:#fff
    classDef explore fill:#1168BD,stroke:#0B4884,color:#fff

    Start([Campaign cycle starts]) --> KS{Kill switch tripped?}:::check
    KS -->|yes| Halt1[Halt: kill_switch]:::halt
    KS -->|no| Budget{Session cost &gt; budget?}:::check
    Budget -->|yes| Halt2[Halt: budget exhausted]:::halt
    Budget -->|no| Canary{Canary failed recently?}:::check
    Canary -->|yes| Halt3[Halt: Judge drift alert]:::halt
    Canary -->|no| RegDue{Regression trigger fired?}:::check

    RegDue -->|yes| RegCamp[Return: regression campaign]:::select
    RegDue -->|no| MVPUnder{Any MVP category<br/>under target coverage?}:::check

    MVPUnder -->|yes| Candidates1[Candidates = MVP under-target]:::select
    MVPUnder -->|no| Candidates2[Candidates = MVP + stretch<br/>stretch weighted lower]:::select

    Candidates1 --> Weight[Weight sub-attacks:<br/>severity_history / 1 + days_since_last_run]:::select
    Candidates2 --> Weight

    Weight --> Eps{rand &lt; epsilon = 0.1?}:::check
    Eps -->|yes| Explore[Pick unrun sub-attack uniformly]:::explore
    Eps -->|no| Greedy[Pick by weighted random]:::select

    Explore --> Allocate[Allocate cost = remaining_budget / remaining_campaigns]:::select
    Greedy --> Allocate
    Allocate --> Dispatch([Return CampaignBrief to Red Team]):::select

    Halt1 --> End([Session halted])
    Halt2 --> End
    Halt3 --> End
```

---

## 8. HITL Approval Flow

How a finding routes through human approval, by severity and confidence.

```mermaid
flowchart TB
    classDef event fill:#FFEB3B,stroke:#F57F17,color:#000
    classDef check fill:#9C27B0,stroke:#6A1B9A,color:#fff
    classDef autoflow fill:#43A047,stroke:#2E7D32,color:#fff
    classDef humanflow fill:#FB8C00,stroke:#E65100,color:#fff
    classDef end_state fill:#1168BD,stroke:#0B4884,color:#fff

    F[Finding produced by Doc Agent]:::event
    SevCheck{Severity in P0 or P1?}:::check
    ConfCheck{Confidence = low?}:::check

    AutoFile[Auto-file to GitLab<br/>P2 or P3 + high confidence]:::autoflow
    Queue[Queue for human approval]:::humanflow
    Notify[Notify operator: CLI / Web UI]:::humanflow

    Decide{Operator decides}:::check
    Approve[Approve]:::humanflow
    Reject[Reject]:::humanflow
    Modify[Modify severity / details]:::humanflow

    GL[Filed as GitLab issue]:::end_state
    GT[Added to Judge ground-truth as 'false positive']:::end_state
    ReFile[Re-file with operator edits]:::humanflow

    F --> SevCheck
    SevCheck -->|yes| Queue
    SevCheck -->|no| ConfCheck
    ConfCheck -->|yes| Queue
    ConfCheck -->|no| AutoFile
    AutoFile --> GL
    Queue --> Notify
    Notify --> Decide
    Decide -->|approve| GL
    Decide -->|reject| GT
    Decide -->|modify| ReFile
    ReFile --> GL
```

**Why this routing is conservative**: a false-positive P0 filed autonomously can damage trust with the AgentForge dev team and damage the platform's standing with the CISO. A false-positive P2 is recoverable (re-classify, close as not-an-issue). The asymmetric cost of being wrong drives the asymmetric routing.

---

## 9. Trust Boundaries in the AgentForge Target

The trust transitions in the target system. This is the surface the platform attacks. Pulled from `THREAT_MODEL.md` and visualized here for the architecture defense.

```mermaid
flowchart TB
    classDef untrusted fill:#D32F2F,stroke:#B71C1C,color:#fff
    classDef semitrusted fill:#FB8C00,stroke:#E65100,color:#fff
    classDef trusted fill:#43A047,stroke:#2E7D32,color:#fff
    classDef inversion fill:#9C27B0,stroke:#6A1B9A,color:#fff

    Browser[User browser]:::untrusted
    Vue[Vue dashboard]:::semitrusted
    BFF[FastAPI BFF /api/agent/*]:::trusted
    LG[LangGraph agent runtime]:::trusted
    LLM[LLM provider Anthropic/OpenAI]:::inversion
    OEM[OpenEMR PHP module]:::trusted
    DB[(MySQL ePHI)]:::trusted
    LF[Langfuse external SaaS]:::semitrusted

    Browser -->|TB1 prompts, uploads, session cookie| Vue
    Vue -->|TB2 authenticated session| BFF
    BFF -->|TB3 retrieved chunks + prompt| LG
    LG -->|TB4 INSTRUCTION-SHAPED content| LLM
    LG -->|TB5 internal JWT, tool call| OEM
    OEM -->|TB6 parameterized query| DB
    LG -->|TB7 trace payload may contain prompt text| LF

    Note1[/"TB4 is the trust inversion: content trusted enough to send is parsed as instructions by the model. Indirect prompt injection lives here."/]:::inversion
    LLM -.- Note1
```

**Trust transitions table**:

| ID | Boundary | What crosses | Trust transition | Relevant attack category |
|---|---|---|---|---|
| TB1 | Browser → Vue | Prompts, uploads, session cookie | Untrusted → semi-trusted (post-auth) | All — entry point |
| TB2 | Vue → BFF | Auth session, prompts | Semi-trusted → trusted-after-auth | Category 2 (authz bypass) |
| TB3 | BFF → LangGraph | Prompt + retrieved context | Trusted (but context contains untrusted material) | Category 1 (indirect injection prep) |
| TB4 | LangGraph → LLM | Full prompt with retrieved content | **Trust inversion** — content becomes instructions | **Category 1** — defining boundary |
| TB5 | LangGraph → OpenEMR module | Internal JWT, tool calls | Trusted (but LLM-influenced) | Category 3 (tool misuse) |
| TB6 | OpenEMR → MySQL | Parameterized queries | Trusted | Category 3 (chart writes) |
| TB7 | LangGraph → Langfuse | Trace payload | Trusted → external | Category 2 (PHI in traces) |

---

## 10. Threat-Surface Coverage Matrix (Architectural View)

How the 3 MVP attack categories map to the AgentForge surfaces. This is the architectural view; the runtime coverage matrix lives in SQLite.

```mermaid
flowchart LR
    classDef cat fill:#1168BD,stroke:#0B4884,color:#fff
    classDef surf fill:#7B5B33,stroke:#5A4327,color:#fff

    C1[Cat 1: Indirect Prompt Injection]:::cat
    C2[Cat 2: PHI Exfil / Authz Bypass]:::cat
    C3[Cat 3: Tool Misuse / Chart Write]:::cat

    S1[POST /api/agent/turn<br/>clinician prompt]:::surf
    S2[POST /api/agent/upload<br/>PDF text/image]:::surf
    S3[RAG corpus retrieval]:::surf
    S4[GET /api/fhir/path<br/>chart reads]:::surf
    S5[Redis agent memory]:::surf
    S6[GET /api/agent/document/id]:::surf
    S7[POST /api/agent/promote<br/>intake to chart]:::surf
    S8[OpenEMR write paths<br/>procedure_*, questionnaire_response]:::surf
    S9[Langfuse traces]:::surf
    S10[sessionStorage]:::surf

    C1 --> S1
    C1 --> S2
    C1 --> S3
    C2 --> S1
    C2 --> S4
    C2 --> S5
    C2 --> S6
    C2 --> S9
    C2 --> S10
    C3 --> S1
    C3 --> S7
    C3 --> S8
```

Surfaces hit by multiple categories (e.g., `/api/agent/turn` is in all three) are higher-leverage targets — defenses there protect more.

---

## 11. Cost Allocation Across Agents (per campaign)

Visualizing where the per-campaign cost goes. Approximate; will be measured during MVP runs.

```mermaid
pie title Per-campaign cost (no finding, ~$0.08)
    "Red Team (GPT-4o)" : 62
    "Judge (Sonnet 4.6)" : 37
    "Orchestrator (Haiku 4.5)" : 2
    "Audited wrapper overhead" : 1
```

```mermaid
pie title Per-campaign cost (with finding, ~$0.12)
    "Red Team (GPT-4o)" : 42
    "Judge (Sonnet 4.6)" : 25
    "Documentation (Sonnet 4.6)" : 33
    "Orchestrator (Haiku 4.5)" : 1
```

Documentation Agent runs only when a finding is produced, which is why it's absent from the no-finding case.

---

## 12. Configuration Surfaces (versioned)

Everything in this list is versioned in git and SHAed into the run manifest. A run is fully reproducible per `(target_sha, prompt_set_sha, rubric_set_sha, attack_library_sha, policy_sha)`.

```mermaid
graph TB
    classDef cfg fill:#F57F17,stroke:#E65100,color:#fff
    classDef agent fill:#1168BD,stroke:#0B4884,color:#fff
    classDef state fill:#7B5B33,stroke:#5A4327,color:#fff

    Targets[targets.yaml<br/>allowlist]:::cfg
    Rubrics[rubrics/&lt;category&gt;.yaml<br/>per-category verdict schema]:::cfg
    AttackLib[attack_library.json<br/>seed payloads]:::cfg
    Prompts[prompts/redteam.md<br/>prompts/judge.md<br/>prompts/orchestrator.md<br/>prompts/doc.md]:::cfg
    OrchPolicy[orchestrator_policy.yaml<br/>coverage targets, epsilon, weights]:::cfg
    DocPolicy[documentation_policy.yaml<br/>HITL thresholds]:::cfg
    Models[models.yaml<br/>per-agent model choice + temp]:::cfg

    RT[Red Team]:::agent
    J[Judge]:::agent
    Orch[Orchestrator]:::agent
    Doc[Documentation]:::agent

    Manifest[(run_manifests row<br/>captures all SHAs)]:::state

    Targets --> RT
    AttackLib --> RT
    Prompts --> RT
    Models --> RT

    Rubrics --> J
    Prompts --> J
    Models --> J

    OrchPolicy --> Orch
    Prompts --> Orch
    Models --> Orch

    DocPolicy --> Doc
    Prompts --> Doc
    Models --> Doc

    Targets -.captures SHA.-> Manifest
    Rubrics -.captures SHA.-> Manifest
    AttackLib -.captures SHA.-> Manifest
    Prompts -.captures SHA.-> Manifest
    OrchPolicy -.captures SHA.-> Manifest
    DocPolicy -.captures SHA.-> Manifest
    Models -.captures SHA.-> Manifest
```

---

## How to read these together

For a **5-minute architecture defense**, walk in this order:

1. **Diagram 1 (Context)** — "this is what the platform is and who uses it."
2. **Diagram 2 (Containers)** — "this is what the platform is made of."
3. **Diagram 3 (Sequence)** — "this is what happens in one run."
4. **Diagram 7 (Decision Tree)** — "this is how the Orchestrator decides what to test next" (answers the most common defender question).
5. **Diagram 8 (HITL)** — "this is where humans stay in the loop and why."
6. **Diagram 9 (Trust boundaries)** — "this is the surface we attack" (ties back to `THREAT_MODEL.md`).

The rest (4, 5, 6, 10, 11, 12) are reference diagrams for follow-up questions.


---

## Companion documents

- [`README.md`](./README.md) — quickstart + project overview
- [`ARCHITECTURE.md`](./ARCHITECTURE.md) — system design and agent roles
- [`THREAT_MODEL.md`](./THREAT_MODEL.md) — attack surface, in-scope vs out-of-scope
- [`USERS.md`](./USERS.md) — operator and CISO journeys
- [`DEFENSE.md`](./DEFENSE.md) — architecture defense (conflict-of-interest separation)
- [`presearch.md`](./presearch.md) — initial scoping notes

*Source of truth for the operational schema: `rubrics/SCHEMA.md`.
Source of truth for the data contracts: `src/agentforge_redteam/state.py`.*
