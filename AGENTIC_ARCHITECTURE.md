# Agentic Architecture — Complete Step-by-Step

## Pattern: ReAct Loop with Function Calling over SSE

This is a custom-built agent (no LangChain/AutoGen) using OpenAI's **function-calling** API in a streaming **ReAct (Reason + Act) loop**.

---

## Step 1: User Sends Message (Frontend)

**`AgentChatBar.tsx`** — `handleSend()`
- User types a message (or clicks a suggestion)
- Frontend builds `conversation_history` from prior messages (role + content pairs)
- Calls `streamAgentChat()` with `{message, session_id, conversation_history}`

## Step 2: SSE Stream Opens (Frontend → Backend)

**`agent.ts`** — `streamAgentChat()`
- Sends `POST /api/agent/stream` with JSON body
- Opens a `ReadableStream` reader on the response
- Parses `data: {...}\n\n` SSE lines and yields typed `AgentSSEEvent` objects
- Frontend processes events in a `for await` loop in real-time

## Step 3: Endpoint Receives Request (Backend)

**`agent_endpoints.py`** — `agent_chat_stream()`
- Validates message + session_id
- Auto-creates a session if none exists (for ad-hoc chat)
- Converts history to OpenAI format
- Returns `StreamingResponse(sse_generator(), media_type="text/event-stream")`
- Inside `sse_generator()`, calls `run_agent_stream()` and yields each SSE chunk

## Step 4: The ReAct Loop Begins (Core Agent)

**`agent_service.py`** — `run_agent_stream()`

```
┌─────────────────────────────────────────────────────────┐
│  MESSAGES = [ system_prompt, ...history, user_message ]  │
│                                                          │
│  for iteration in 1..20:                                 │
│    ┌──────────────────────────────────┐                  │
│    │ Call Azure OpenAI (streaming)     │                  │
│    │  model: gpt-5-mini               │                  │
│    │  tools: 19 AGENT_TOOLS           │                  │
│    │  tool_choice: "auto"             │                  │
│    │  stream: true                    │                  │
│    └──────────┬───────────────────────┘                  │
│               │                                          │
│     ┌─────────▼─────────┐                                │
│     │ Stream chunks      │                               │
│     │ - delta.content → yield SSE {type: "token"}        │
│     │ - delta.tool_calls → accumulate tool call args     │
│     └─────────┬─────────┘                                │
│               │                                          │
│     ┌─────────▼─────────────────────┐                    │
│     │ finish_reason == "tool_calls"? │                    │
│     └──┬──────────────────┬─────────┘                    │
│        │ YES              │ NO (finish_reason == "stop")  │
│        │                  │                               │
│        ▼                  ▼                               │
│   [TOOL BRANCH]     [DONE BRANCH]                        │
│                      yield SSE {type: "done"}            │
│                      return                               │
└─────────────────────────────────────────────────────────┘
```

## Step 5: Tool Execution Branch (when LLM chooses tools)

When the LLM returns `finish_reason: "tool_calls"`:

```
1. Append assistant message (with tool_calls) to MESSAGES

2. For each tool call:
   a. yield SSE {type: "tool_call", name: "inspect_xslt", arguments: {...}}
   b. yield SSE {type: "file_activity", action: "reading", file_type: "xslt"}

3. Execute ALL tool calls in PARALLEL via asyncio.gather()
   → TOOL_HANDLERS[tool_name](args, app_state)

4. For each result:
   a. yield SSE {type: "tool_result", name: "...", result: {...}}
   b. If inspect tool → yield file_activity "read_complete" with preview
   c. If fix/patch tool → yield file_activity "saved" + artifact update:
      - yield SSE {type: "xslt_update", xslt: "...", description: "..."}
      - yield SSE {type: "idoc_update", output: "...", description: "..."}
      - yield SSE {type: "edi_xml_update", edi_xml: "...", description: "..."}
   d. Append {role: "tool", content: JSON(result)} to MESSAGES

5. LOOP BACK → LLM sees tool results, may call more tools or respond
```

## Step 6: Tool Registry (19 tools across 4 layers)

```
TOOL_HANDLERS = {
  # Session
  "inspect_session"        →  Read session state (metadata, artifacts available)

  # Layer 0: Raw EDI
  "inspect_edi_content"    →  Parse & return EDI segments, filter by tag

  # Layer 1: EDI XML
  "inspect_edi_xml"        →  Read intermediate XML
  "fix_edi_xml"            →  Full replace of XML
  "patch_edi_xml"          →  Targeted insert/replace in XML

  # Layer 2: XSLT
  "inspect_xslt"           →  Read XSLT code
  "fix_xslt"               →  Full XSLT rewrite
  "patch_xslt"             →  Targeted edits (insert_after/before/replace/replace_all)

  # Layer 3: IDoc Output
  "inspect_idoc_output"    →  Read IDoc/EDI XML output
  "fix_idoc_output"        →  Full replace
  "patch_idoc_output"      →  Targeted edits

  # Cross-Layer Diagnostics
  "diagnose_pipeline"      →  Multi-layer issue scanner (segments/identifiers/dates/fields)
  "trace_field"            →  Trace one field through all layers
  "re_run_transformation"  →  Re-execute XSLT pipeline and return new output
  "validate_xml"           →  XML well-formedness check

  # Knowledge
  "lookup_edi_standard"    →  EDIFACT/X12/IDoc reference lookup

  # DB Versioning (TEMP_MAPPING_STORE)
  "list_temp_mappings"     →  List all stored XSLTs
  "fetch_temp_mapping"     →  Load XSLT into session by ID
  "save_temp_mapping"      →  Save as new versioned row
}
```

## Step 7: Frontend Processes SSE Events (Real-Time)

**`AgentChatBar.tsx`** — the `for await` switch:

| SSE Event | Frontend Action |
|---|---|
| `token` | Append text to streaming message bubble |
| `tool_call` | Push to `toolSteps[]` → renders as collapsible tool chips |
| `tool_result` | Push result to `toolSteps[]` → shows tool output |
| `xslt_update` | Calls `onXsltUpdate()` → refreshes XSLT in main panel |
| `idoc_update` | Calls `onIdocUpdate()` → refreshes IDoc in main panel |
| `edi_xml_update` | Calls `onEdiXmlUpdate()` → refreshes EDI XML in main panel |
| `file_activity` | Updates live file activity indicator (reading/editing/saved) |
| `done` | Mark message complete, stop streaming cursor |
| `error` | Show error in message bubble |

## Step 8: Session State (Shared Between Agent & Pipeline)

All tools read/write a shared **in-memory session** keyed by `session_id`:

```
session = {
  file_content:     "raw EDI text",
  upload_metadata:  {sender_id, message_type, direction, ...},
  selected_match:   {xslt_code, ...},
  generated_xslt:   "...",
  merged_xslt:      "...",
  idoc:             {idoc_content: "..."},
  edi_xml:          "...",
  temp_mapping_id:  "...",
  ...
}
```

Both the main pipeline endpoints (`/api/edi/upload`, `/api/edi/generate-xslt`, etc.) and the agent tools operate on the **same session**, so the agent can inspect and fix artifacts the pipeline created.

## Step 9: Safety & Limits

- **Max 20 iterations** per message (loop cap)
- **Last iteration forces text** — `tool_choice` removed so LLM must respond
- **Tool results truncated** to 6000 chars before appending to messages
- **SSE payloads truncated** to 2500 chars per field for transmission
- **Parallel tool execution** — multiple tools in one turn run via `asyncio.gather()`
- **Temperature 0.0** — deterministic, no hallucinated fixes

---

## Visual Summary

```
┌──────────────────────────────────────────────────────────────┐
│                        FRONTEND                               │
│  AgentChatBar.tsx                                             │
│    ├── User types message                                     │
│    ├── buildHistory() → prior messages                        │
│    └── streamAgentChat() ─── POST /api/agent/stream ──────┐  │
│         │                                                  │  │
│         │  for await (event of stream):                    │  │
│         │    token → append to bubble                      │  │
│         │    tool_call → show tool chip                    │  │
│         │    tool_result → show result                     │  │
│         │    xslt_update → refresh main XSLT panel        │  │
│         │    idoc_update → refresh main IDoc panel         │  │
│         │    file_activity → show live activity indicator  │  │
│         │    done → finalize message                       │  │
└─────────┼──────────────────────────────────────────────────┘  │
          │          SSE stream (text/event-stream)              │
┌─────────┼─────────────────────────────────────────────────────┘
│         ▼                                                     │
│  ┌── agent_endpoints.py ──┐                                   │
│  │  POST /api/agent/stream │                                  │
│  │  → run_agent_stream()   │                                  │
│  └────────┬────────────────┘                                  │
│           ▼                                                   │
│  ┌── agent_service.py ── ReAct Loop (max 20 iterations) ──┐  │
│  │                                                         │  │
│  │  messages = [system_prompt, history, user_msg]          │  │
│  │                                                         │  │
│  │  while iterations < 20:                                 │  │
│  │    Azure OpenAI (gpt-5-mini, streaming, tools=19)       │  │
│  │         │                                               │  │
│  │         ├─ tokens → yield SSE                           │  │
│  │         │                                               │  │
│  │         ├─ tool_calls? ──► execute in parallel          │  │
│  │         │    ├─ inspect_session                         │  │
│  │         │    ├─ inspect_edi_content                     │  │
│  │         │    ├─ patch_xslt                              │  │
│  │         │    ├─ re_run_transformation                   │  │
│  │         │    └─ ... (19 tools)                          │  │
│  │         │    results → yield SSE → append to messages   │  │
│  │         │    LOOP BACK ↩                                │  │
│  │         │                                               │  │
│  │         └─ stop? ──► yield SSE {done} ──► return        │  │
│  └─────────────────────────────────────────────────────────┘  │
│                        BACKEND                                │
└───────────────────────────────────────────────────────────────┘
```
