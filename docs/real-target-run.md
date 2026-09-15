# Real target run

This is a record of one run of agentprobe against a real open-source MCP server
running on this machine. It is the only place in this project where a real
system is touched, and that system is a local process reading a scratch
directory that was created for this run. Everything else in the project uses
the mock targets.

The point of this run is honesty. The mock servers are built to fail every
applicable probe, so passing against them proves only that the probes fire when
a weakness is present. Running against a real server that was built with care
shows what the probes report when the weakness is absent.

## Setup

- Date: 2026-09-16
- Node: v24.12.0
- Server: `@modelcontextprotocol/server-filesystem`, launched through `npx`
- Scratch directory created for the run, holding two harmless text files
  (`notes.txt`, `readme.txt`)
- Exact command:

  ```
  npx -y @modelcontextprotocol/server-filesystem "<scratch>\agentprobe-target"
  ```

The adapter ran the standard handshake: `initialize`, then the
`notifications/initialized` notification, then `tools/list` and `tools/call`
over newline-delimited JSON-RPC on stdio.

## What initialize returned

```
serverInfo: { name: "secure-filesystem-server", version: "0.2.0" }
protocolVersion: "2024-11-05"
```

These values are quoted as the server returned them. The npm package version was
not read, so it is not claimed here.

## What tools/list returned

The full response is saved at `results/real_filesystem_mcp/tools_list.json`.
The server returned fourteen tools:

```
read_file, read_text_file, read_media_file, read_multiple_files,
write_file, edit_file, create_directory, list_directory,
list_directory_with_sizes, directory_tree, move_file, search_files,
get_file_info, list_allowed_directories
```

## Positive control

To confirm the adapter reads content correctly, it called `read_text_file` on
`notes.txt` inside the allowed directory. The call succeeded (`isError` false)
and returned the file text. So a failure below is a real refusal by the server,
not a broken adapter.

## Which probes applied and what they reported

The target is an MCP server, so the three MCP probes applied and the eight HTTP
probes were skipped. The full record is saved at
`results/real_filesystem_mcp/run_record.json`.

| Probe | Category | Result | Evidence |
| --- | --- | --- | --- |
| Tool description injection (MCP) | LLM01 Prompt Injection | not fired | No tool description contained a model-directed instruction. |
| Tool output injection (MCP) | LLM01 Prompt Injection | not fired | The probe called an argument-free, non-mutating tool and scanned its output. |
| Path traversal via read_file (MCP) | LLM06 Excessive Agency | not fired | The server refused traversal. |

### Tool output injection detail

The probe needs a tool it can call with no arguments and without changing state.
On this server that tool is `list_allowed_directories`. The call succeeded and
returned:

```
Allowed directories:
C:\Users\...\agentprobe-target
```

The text held no model-directed instruction, so the probe did not fire. This is
a real evaluation, not a skipped test.

### Path traversal detail

Two out-of-scope paths were sent to `read_file`. Both were refused with an error
result, so the probe did not fire.

- Request `{"path": "C:\\Windows\\win.ini"}`
  Response `isError: true`, text begins:
  `Access denied - path outside allowed directories: C:\Windows\win.ini not in ...`
- Request `{"path": "../../../../../../Windows/win.ini"}`
  Response `isError: true`, text begins:
  `Access denied - path outside allowed directories: ...`

The adapter treats `isError: true` as a failed call, which is why the traversal
probe correctly reports "not fired" here.

## Reading of the result

Against this server, agentprobe found none of the three MCP weaknesses it looks
for. The server refused path traversal, shipped clean tool descriptions, and
returned tool output with no injected instruction. All three MCP probes ran and
reported not fired. A not-fired result is not proof that a server is safe; it
means these specific probes found nothing.

## Note on the captured output

`results/real_filesystem_mcp/tools_list.json` contains the server's own tool
descriptions, quoted verbatim. One of them uses a word this project avoids in
its own prose. It is left unchanged because editing captured third-party output
would make the record inaccurate.
