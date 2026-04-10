# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BV-BRC Workspace Service - A JSONRPC microservice for managing user file/object workspaces with MongoDB persistence and Shock file storage integration.

**Tech Stack**: Perl (primary implementation), Python/JavaScript (auto-generated clients), Go (FUSE filesystem tool)

## Build Commands

```bash
make                    # Build everything (bin, compile-typespec, service)
make compile-typespec   # Regenerate clients from Workspace.spec
make test               # Run test suite (requires MongoDB and Shock)
make deploy             # Deploy service to /kb/deployment
make jarfile            # Build Java client
```

### Running Tests

```bash
# All tests
make test

# Specific test file
$KB_RUNTIME/bin/perl t/client-tests/tests.t
```

Tests require a running MongoDB instance and Shock API connection. Configure via `test.cfg`.

## Architecture

### Services (3 PSGI applications)
- **Workspace** (port 7125): Main service - create, get, ls, copy, delete, permissions
- **WorkspaceDownload** (port 7129): Unauthenticated file downloads with expiring URLs
- **WorkspaceCompletion** (port 7140): Auto-completion support

### Key Files

| File | Purpose |
|------|---------|
| `Workspace.spec` | **API specification** - source of truth for JSONRPC interface |
| `lib/Bio/P3/Workspace/WorkspaceImpl.pm` | Core implementation (~5400 lines) |
| `lib/Bio/P3/Workspace/Service.pm` | JSONRPC handler entry point |
| `lib/Bio/P3/Workspace/WorkspaceClient.pm` | **Auto-generated** - do not edit |
| `lib/Bio/P3/Workspace/WorkspaceClientExt.pm` | Hand-written client extensions (caching, compression detection) |
| `lib/Bio/P3/Workspace/ScriptHelpers.pm` | Helpers for CLI scripts |
| `lib/Workspace.psgi` | Main service PSGI app |
| `deploy.cfg` / `test.cfg` | Configuration files |

### Code Generation

`compile_typespec` generates clients from `Workspace.spec`:
- `lib/Bio/P3/Workspace/WorkspaceClient.pm` (Perl)
- `lib/biop3/Workspace/WorkspaceClient.py` (Python)
- `lib/javascript/Workspace/WorkspaceClient.js` (JavaScript)

**Never edit generated files directly** - modify `Workspace.spec` and run `make compile-typespec`.

### Workspace Path Format

Paths follow the format: `/<owner>@patricbrc.org/<workspace_name>/<path/to/object>`

Examples:
- `/myuser@patricbrc.org/home` - User's home workspace
- `/myuser@patricbrc.org/home/myfile.fa` - File in home workspace

### ObjectMeta Tuple

API responses return ObjectMeta tuples with 13 fields:
```
[ObjectName, ObjectType, FullObjectPath, Timestamp, ObjectID,
 Username, ObjectSize, UserMetadata, AutoMetadata,
 user_permission, global_permission, shockurl, error]
```

Permissions: `w` (write), `r` (read), `a` (admin), `n` (none), `p` (public)

### MongoDB Collections
- **workspaces**: Workspace metadata, permissions, ownership
- **objects**: File/folder objects with metadata and Shock references
- **download_keys**: Expiring download tokens for unauthenticated access

### Data Flow
1. Client calls JSONRPC method via WorkspaceClient
2. Service.pm validates token and dispatches to WorkspaceImpl.pm
3. WorkspaceImpl queries MongoDB for metadata
4. Large files stored in/retrieved from Shock API
5. Results returned as JSON

## Code Patterns

### Private helper methods (prefix with `_`)
- `_getUsername()` - Get authenticated user from context
- `_validateargs($args, \@mandatory, \%optional)` - Validate API parameters
- `_check_ws_permissions()` - Verify access rights
- `_mongodb()` - Get database connection handle
- `_parse_ws_path($path)` - Parse workspace paths into components
- `_error($msg)` - Throw error (dies with `_ERROR_message_ERROR_` wrapper)

### Adding API Methods
1. Define in `Workspace.spec` with authentication requirements (`authentication required/optional`)
2. Implement in `WorkspaceImpl.pm`
3. Run `make compile-typespec`
4. Add tests

## CLI Scripts

Two command families exist in `scripts/`:
- **p3-*** - Modern BV-BRC commands: `p3-ls`, `p3-cp`, `p3-cat`, `p3-mkdir`, `p3-rm`, `p3-du`, `p3-exists`
- **ws-*** - Legacy workspace commands: `ws-ls`, `ws-cp`, `ws-cat`, `ws-mkdir`

Service scripts in `service-scripts/` (p3x-*) are for admin/internal use.

## Go Implementation

Located in `go/` - implements a cross-platform FUSE filesystem for mounting workspaces locally.

### Build Requirements
- CGO is required (uses cgofuse)
- Platform-specific FUSE libraries needed:
  - **Linux**: `fuse3` package
  - **macOS**: macFUSE (`brew install macfuse`)
  - **Windows**: WinFsp

```bash
cd go
make deps       # Download Go dependencies
make build      # Build for current platform (recommended)
make test       # Run tests
```

Cross-compilation is complex due to CGO; best to build on target platform.

## Configuration

The `[Workspace]` section in `deploy.cfg`/`test.cfg` contains:

| Key | Description |
|-----|-------------|
| `shock-url` | Shock API endpoint for large file storage |
| `mongodb-host` | MongoDB server hostname |
| `mongodb-database` | MongoDB database name |
| `mongodb-user` / `mongodb-pwd` | MongoDB credentials (use `null` for no auth) |
| `db-path` | Local filesystem path for small object storage |
| `download-url-base` | Base URL for download service |
| `download-lifetime` | Expiring download URL lifetime in seconds |

## Setup Requirements

1. MongoDB instance running
2. Shock server running
3. Configure `deploy.cfg` with connection details
4. Set `KB_DEPLOYMENT_CONFIG` environment variable
5. Start service: `/kb/deployment/services/Workspace/start_service`

Check `/var/log/syslog` for debugging if service fails to start.
