# OptimClaw Lazy Tool Loading

## Overview

Lazy tool loading is an optimization that dramatically reduces the initial system prompt size sent to the LLM. Instead of injecting full JSON schemas for every available tool into each request, OptimClaw loads only a small core set of tools eagerly and defers the rest until the LLM requests them.

**Impact:** System prompt size drops from approximately 13,000 tokens to approximately 4,000 tokens -- a 70% reduction. This saves cost on every LLM call and leaves more of the context window available for conversation history and tool outputs.

## How to Enable

Set the environment variable:

```bash
export OPTIMCLAW_LAZY_TOOLS=1
```

Or add it to `~/.optimclaw/.env`:

```env
OPTIMCLAW_LAZY_TOOLS=1
```

To disable (default behavior -- all tools loaded eagerly):

```bash
export OPTIMCLAW_LAZY_TOOLS=0
# or simply unset it
unset OPTIMCLAW_LAZY_TOOLS
```

## Core Tools (Always Loaded)

When lazy loading is enabled, the following 12 core tools are always included in the system prompt. These are the tools the LLM needs most frequently and cover the essential interaction patterns:

| # | Tool | Purpose |
|---|------|---------|
| 1 | `echo` | Return text to the user |
| 2 | `time` | Get current date and time |
| 3 | `json` | Parse and query JSON data |
| 4 | `http` | Make HTTP requests to allowed endpoints |
| 5 | `web_fetch` | Fetch and extract content from web pages |
| 6 | `file_read` | Read files from the workspace |
| 7 | `file_write` | Write files to the workspace |
| 8 | `shell` | Execute shell commands in the sandbox |
| 9 | `memory_search` | Search persistent memory (hybrid FTS + vector) |
| 10 | `memory_write` | Write to persistent memory |
| 11 | `message` | Send messages to channels |
| 12 | `tool_info` | Discover and load additional tools on demand |

## Tool Discovery with tool_info

The `tool_info` tool is the mechanism by which the LLM discovers and loads deferred tools. When the LLM determines it needs a tool that is not in its current context, it calls `tool_info` to retrieve the full schema.

### How It Works

1. The system prompt includes a brief note listing the names of all available (but not yet loaded) tools.
2. When the LLM needs one of these tools, it calls `tool_info` with the tool name or a search query.
3. `tool_info` returns the full JSON schema (parameters, description, examples) for the matched tools.
4. The LLM can then call the newly loaded tool in subsequent turns.

### tool_info Parameters

```json
{
  "name": "tool_info",
  "parameters": {
    "query": {
      "type": "string",
      "description": "Exact tool name or keyword search query"
    },
    "max_results": {
      "type": "number",
      "description": "Maximum tools to return (default: 5)"
    }
  }
}
```

### Example Flow

**System prompt includes:**
> Additional tools available (use `tool_info` to load): `job_create`, `job_status`, `job_cancel`, `routine_create`, `routine_list`, `skill_search`, `skill_install`, `extension_install`, `secrets_set`, `secrets_get`, ...

**LLM decides it needs to create a background job:**

```
LLM -> tool_info(query="job_create")

tool_info returns:
{
  "tools": [{
    "name": "job_create",
    "description": "Create a new background job with the given prompt and priority",
    "parameters": {
      "prompt": { "type": "string", "required": true },
      "priority": { "type": "number", "default": 5 },
      "timeout_secs": { "type": "number", "default": 300 }
    }
  }]
}

LLM -> job_create(prompt="Summarize today's news", priority=3)
```

## When to Use Lazy Loading

| Scenario | Recommendation |
|----------|----------------|
| Production deployment with many tools/MCP servers | Enable -- significant token savings |
| Development and debugging | Disable -- easier to see all available tools |
| Cost-sensitive usage with expensive models | Enable -- reduces per-request cost |
| Clusters with heterogeneous tool sets | Enable -- each node may have different tools |
| Simple setups with few tools (<15 total) | Either -- minimal difference |

## Performance Characteristics

- **First request:** Faster, because the system prompt is smaller and the LLM processes fewer tokens.
- **Tool discovery round-trip:** When the LLM calls `tool_info`, it adds one extra turn before the actual tool call. In practice this is rare because the 12 core tools handle the majority of interactions.
- **Subsequent requests in the same session:** Tool schemas loaded via `tool_info` remain in the conversation context for the duration of the session, so discovery cost is paid at most once per tool per session.

## Interaction with Other Features

- **MCP tools:** MCP-connected tool schemas are also deferred when lazy loading is enabled. They appear in the "additional tools available" list and are loaded via `tool_info`.
- **WASM tools:** Same behavior as MCP tools -- deferred and discoverable.
- **Skills:** Skill tools (`skill_list`, `skill_search`, `skill_install`, `skill_remove`) are deferred. The skill system itself is unaffected.
- **Mesh cluster:** Lazy loading is a per-node setting. Different nodes in a cluster can have different settings.
