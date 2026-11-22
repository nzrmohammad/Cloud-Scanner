# AGENTS.md — Cloud Scanner Architecture & Agent Instructions

This document is the authoritative guide for AI coding agents and human engineers working on **Cloud Scanner**. It outlines the project's architecture, conventions, known traps, and the step-by-step technical roadmap.

---

## 1. Project Overview & Architecture

**Cloud Scanner** is a specialized, high-performance scanning tool designed to discover, validate, benchmark, and rank clean Cloudflare Anycast IP addresses for censorship circumvention (VLESS over TLS, WebSocket, gRPC, HTTPUpgrade, SplitHTTP, and Reality) utilizing `Xray-core`.

### Core Architectural Layers

```
+-------------------------------------------------------------+
|                      User Interfaces                        |
|  - Interactive TUI (Rich, keyboard navigation, menus)       |
|  - Headless / Config-Driven Engine (CLI via config.txt)     |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                       scanner.engine                        |
|  - Fast TCP Pre-filter                                      |
|  - Latency & Jitter Testing                                 |
|  - Anti-Drop / Longevity DPI Endurance Testing              |
|  - Multi-threaded Speed Benchmarking (Download & Upload)     |
+---------------+------------------------------+---------------+
                |                              |
                v                              v
+-------------------------------+ +---------------------------+
|         scanner.xray          | |     scanner.analytics     |
| - VLESS Link Parser/Generator | | - Statistical Analysis    |
| - XrayProcess Context Manager | | - Sorting & Ranking       |
| - Config JSON Generator       | | - Smart Recommendations   |
+-------------------------------+ +---------------------------+
                |                              |
                v                              v
+-------------------------------+ +---------------------------+
|        scanner.targets        | |       scanner.geoip       |
| - CIDR/IP Range Parsers       | | - GeoIP & ISP Resolution  |
| - ISP Profile Selectors       | | - Cloudflare Colo (Trace) |
+-------------------------------+ +---------------------------+
```

---

## 2. Repository Layout & Module Map

| File / Directory | Purpose & Responsibility |
| :--- | :--- |
| `main.py` | Application entry point: initializes terminal, checks dependencies, launches app. |
| `scanner/app.py` | CLI & interactive TUI orchestrator, argument parser, post-scan execution life cycle. |
| `scanner/logger.py` | Centralized rotating logging handler writing to `results/scanner.log`. |
| `scanner/models.py` | Pure dataclasses: `ScanResult`, `VlessConfig`, `AppSettings`, `SmartRecommendation`. |
| `scanner/constants.py` | Default settings, Cloudflare PoP/Colo airport dictionaries, default config template. |
| `scanner/config.py` | `config.txt` loader, VLESS URL generator/serializer, runtime settings validator. |
| `scanner/xray.py` | Core Xray management: binary locator, asset checks, `XrayProcess` lifecycle manager. |
| `scanner/engine.py` | Multi-threaded network testing engine: TCP probing, latency, speed, endurance. |
| `scanner/analytics.py` | Result ranking algorithms, multi-key sorting, smart recommendation categories. |
| `scanner/targets.py` | IP range loader: parses CIDR, ranges (`A.B.C.D-E`), single IPs, and random sampling. |
| `scanner/geoip.py` | Resolves IP geolocation (ipinfo.io / freeipapi) and edge node metadata with local cache. |
| `scanner/storage.py` | Exports results to formatted text lists (`clean_ips.txt`), CSVs, and VLESS links. |
| `scanner/ui/terminal.py`| Console abstraction, Rich console instance, screen clearing, stage headers. |
| `scanner/ui/menus.py` | Arrow-key driven interactive menus with keyboard navigation and pagination. |
| `scanner/ui/screens.py`| Step-by-step TUI screens: welcome, ISP selection, scan progress, report viewers. |
| `scanner/ui/keys.py` | Cross-platform raw keyboard input handling (`msvcrt` on Windows, `termios` on Unix). |
| `ip-ranges/` | Bundled CIDR and IP range lists for target internet service providers (ISPs). |
| `core/` | Default directory for `xray` binary and routing database assets (`geoip.dat`, `geosite.dat`). |
| `results/` | Output directory where CSV reports, IP lists, and recommended configs are persisted. |
| `tests/` | Comprehensive automated test suite (125 tests across 10 modules). |
| `pyproject.toml` | Project metadata, build config, linter (`ruff`), and testing (`pytest`) configurations. |

---

## 3. Strict Development Guidelines & Anti-Patterns

Any agent making changes to this codebase must adhere strictly to the following rules:

### A. Subprocess Management (`XrayProcess`)
- **NEVER** spawn ad-hoc `subprocess.Popen([xray, ...])` inside `engine.py`, `screens.py`, or any new module.
- **ALWAYS** use the `XrayProcess` context manager from `scanner.xray`:
  ```python
  from scanner.xray import XrayProcess

  with XrayProcess(xray_path, vless_config, server_ip, port, timeout=3.0) as xp:
      # SOCKS proxy is verified open; use xp.proxies or xp.socks_url
      response = requests.get(test_url, proxies=xp.proxies, timeout=timeout)
  # Process termination and temp directory cleanup are handled cleanly and automatically
  ```

### B. Engine & UI Separation (Zero Console Coupling)
- `scanner/engine.py`, `scanner/analytics.py`, and `scanner/xray.py` must remain **headless**.
- **NEVER** import `console` or call `console.print()` or `render_stage()` directly inside `engine.py`.
- Progress tracking and user feedback must be handled through callbacks, events, or generators passed from the UI layer (`scanner/ui/`).

### C. Windows Terminal & OS Compatibility
- **Never call `os.system("cls")`** for redraws or frame updates. It spawns a sub-shell, causes screen flicker, and wipes terminal scrollback history. Use ANSI cursor escape sequences or `rich.live.Live`.
- **Keyboard Interrupts on Windows**: In `scanner/ui/keys.py`, `msvcrt.getwch()` returns `\x03` on `Ctrl+C`. You **must** explicitly check for `\x03` and raise `KeyboardInterrupt`.
- **Worker Limits**: Do not exceed 20–30 concurrent workers by default on Windows to prevent TCP port exhaustion (`WSAENOBUFS` / `WSAEADDRINUSE`).
- **Emoji & Box Drawing Fallbacks**: Ensure terminal tables degrade cleanly to plain ASCII (`+---`, `|`) if wide unicode / emoji support is absent.

### D. Measurement & Statistical Rigor
- **Latency**: Do not rely solely on arithmetic mean. Use `median`, `p90`, and `stddev`.
- **Jitter**: Jitter must follow standard network definitions (RFC 3393 / RFC 3550): mean absolute difference between successive packet samples (`sum(|D(i) - D(i-1)|) / (N - 1)`), **not** deviation from the sample mean.
- **Speed Benchmarking**: Always implement a lightweight warm-up burst to establish TCP window size, and separate Time-To-First-Byte (TTFB) from transfer throughput.
- **Anti-Drop / DPI Longevity**: Never use repeated tiny `generate_204` requests. DPI firewalls throttle sustained flows. Longevity tests must stream a continuous payload over 30–60 seconds, evaluating packet drop rate as a percentage threshold (e.g., loss <= 5%) rather than a binary all-or-nothing test.

### E. Error Handling & Logging
- **Zero Silent Suppressions**: Eliminate all `except Exception: pass` patterns.
- Log caught exceptions with descriptive messages and context using Python's standard `logging` library.
- Populate `ScanResult.error` with meaningful diagnostics instead of discarding error state.

---

## 4. Implementation Roadmap & Status

### Phase 0: Quick Critical Bug Fixes (Completed)
- [x] Fixed `sustained=None` sorting score priority (`True` (0.0) < `None` (1.0) < `False` (2.0)).
- [x] Implemented safe formatting helpers (`_fmt_ms`, `_fmt_loss`) preventing crashes on `None` latencies.
- [x] Added `speed_workers = 6` to default configurations and templates.
- [x] Supported `allowInsecure` and `insecure` in VLESS query parameters.
- [x] Standardized Mbps calculation to decimal networking standard ($1\text{ MB} = 1,000,000\text{ bytes}$).

### Phase 1: Measurement Rigor & Accuracy (Completed)
- [x] Expanded default `top_targets` to 30 endpoints.
- [x] Multi-sample latency with jittered inter-sample spacing.
- [x] Statistical latency metrics (`median`, `p90`, and consecutive RFC 3393 jitter).
- [x] Download warm-up burst, TTFB isolation, and median filtering across bursts.
- [x] DPI endurance / anti-drop testing with percentage loss evaluation.

### Phase 2: Engineering Quality, Testing & Refactoring (Completed)
- [x] Configured `pyproject.toml` with `ruff` and `pytest`.
- [x] Automated test suite covering targets, analytics, config, xray, geoip, engine, menus, and storage.
- [x] Refactored all subprocess calls to use `XrayProcess`.
- [x] Central rotating file logger writing to `results/scanner.log`.

### Phase 3: Persistent GeoIP & Colo Caching (Completed)
- [x] Disk cache at `results/geoip_cache.json` with thread-safe atomic writes.
- [x] Local fallback parsing `core/geoip.dat`.
- [x] Rate limit handling and cooldowns for remote GeoIP providers.

### Phase 4: UI/UX & Terminal Polish (Completed)
- [x] Flicker elimination: replaced full-screen clears with `rich.live.Live` and ANSI sequences.
- [x] Consistent panel styling, `box.ROUNDED`, and persistent fixed stage headers.
- [x] Dynamic pagination and display limits (50 endpoints).
- [x] Immediate `Ctrl+C` handling via `msvcrt.getwch()` on Windows.

### Phase 5: Video Streaming Optimization & Advanced Rigor (Completed)
- [x] **Video Streaming Sorting & Ranking**:
  - `full_sort_key` and Streaming recommendations rank connection stability (`sustained`, packet loss bracket <= 3%, jitter bracket <= 15ms) ahead of raw burst speed.
  - Streaming recommendation fallback evaluates actual stability/jitter instead of arbitrary pick.
- [x] **True Longevity Endurance Testing**:
  - Longevity testing tracks actual cumulative stall duration across the full duration rather than aborting prematurely on the first timeout.
- [x] **Consecutive RFC Jitter & Handshake Isolation**:
  - Calculated RFC 3393 jitter strictly across consecutive successful samples without bridging over dropped packets.
  - Added warm-up probe before latency sampling so handshake latency doesn't inflate keep-alive jitter.
- [x] **xHTTP Mode Parameter & Migration**:
  - Supported `mode` query parameter in VLESS URI for xHTTP/splithttp and migrated splithttp to xhttp for Xray >= 24.12.18.
- [x] **CLI & TUI Defaults Parity**:
  - Aligned CLI arguments (`--speed-mb 3`, `--recheck-samples 8`, `--speed-workers 6`) with `AppSettings`.
- [x] **Task Exception Resilience & Cleanup**:
  - `_run_concurrent_tasks` records failed results and increments counter when unhandled task exceptions occur.
  - Eliminated bare `except Exception: pass` patterns across logger, terminal, screens, and main.
  - Eliminated redundant double-saving of `clean_ips` in CLI mode.

### Phase 6: Concurrency Safety, Process Lifecycle & Artifact Integrity (Completed)
- [x] **Thread-Safe Local Port Registry & Allocation Collision Mitigation**:
  - Maintained `_RESERVED_LOCAL_PORTS` under `_PORT_LOCK` and proactive socket reservation to minimize port reuse races among concurrent workers.
  - Added strict post-poll verification in `wait_ports` and reactive retry on transient bind collision so collisions never latch onto other instances' SOCKS ports.
- [x] **Windows Win32 Job Object & Process Lifecycle Management**:
  - Bound spawned `xray.exe` instances to a Win32 Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` on Windows, preventing orphaned child processes on exit.
  - Synchronized `_BaseXrayProcess.close()` via instance lock and active process tracking for reliable termination.
- [x] **Stale Artifact Overwrite & Output Hygiene**:
  - Overwrite stale `{filename_prefix}_vless.txt` and clean per-port directories when a scan produces no working endpoints.
  - Overwrite `recommended_configs.txt` with clear notice when no recommendations qualify.
  - Guaranteed continuous section numbering (1 to 5) in `scan_summary_report.txt` and masked sensitive credentials (`uuid[:8] + "..."`).
  - Formatted raw Python exception tuple reprs into concise error messages.
- [x] **Security Hardening & Input Validation**:
  - Replaced arbitrary path resolution with UNC path rejection (`\\`, `//`) in `parse_vless`, `_resolve_target_file`, and `output_dir`.
  - Added upper bounds to integer config options with `OverflowError` protection against malformed floats.
  - URL-encoded UUID fields against reserved query delimiters.

### Phase 7: Real-Core Protocol Compliance, CLI Parity & Asset Hygiene (Completed)
- [x] **Xray-Core Protocol Correctness & Adaptation**:
  - Verified configurations with actual `xray.exe` 26.11.9 (`-test` / `-dump`).
  - Fixed version adaptation thresholds (HTTP->xHTTP from 24.12.18, `allowInsecure` removal around 26.1.31, adapting `alpn` during migration).
  - Corrected `network=xhttp` generation (`xhttpSettings`) and sanitized legacy SplitHTTP modes (`mode=multi` -> `auto`).
  - Protocol-level validation for `flow` (omitted on non-tcp or non-tls/reality to prevent silent connection termination).
  - Validated REALITY outbound: required `pbk` public key and transport restrictions (`tcp`, `xhttp`, `grpc`).
  - Fixed empty `encryption` parameter defaulting to `"none"`.
  - Extracted host header from JSON `headers` query parameter in VLESS URIs.
  - Enabled `"udp": True` on SOCKS inbounds for UDP ASSOCIATE and QUIC compatibility.
- [x] **CLI & Config Integration Parity**:
  - CLI `run_cli` honors `config.txt` settings (`ports`, `post_scan_mode`, `workers`, `timeout`, `speed_workers`, etc.) when flags are omitted.
  - Curated smart recommendations (`recommended_configs.txt`) exported in CLI mode.
  - Synchronized comments and values in `config.txt`.
- [x] **IP Ranges & Script Hygiene**:
  - Removed misplaced IPv6 `/29` subnet from IPv4 range files, isolating it cleanly in `ip-ranges/ipv6/`.
  - Fixed `%errorlevel%` expansion in `run.bat` using `if errorlevel 1`.
  - Made launcher `pip install` conditional on missing imports in `run.bat` and `run.sh`.
  - Synchronized dependency version specifications between `pyproject.toml` and `requirements.txt`.

---

## 5. Verification Checklist for Agents

Before completing any task or PR:
- [ ] `pytest tests/` passes completely with zero failures.
- [ ] `ruff check .` reports no lint errors.
- [ ] Manual test run on Windows PowerShell (`python main.py`) confirms no flicker, responsive `Ctrl+C`, and clean exit.
- [ ] Results files (`results/clean_ips.txt`, `results/clean_ips.csv`) are generated correctly without malformed links.
- [ ] No zombie `xray.exe` or `xray` processes remain in the operating system process list.
