# 🌐 Cloud Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Architecture-Modular%20OOP-success.svg?style=for-the-badge" alt="Modular OOP" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-informational.svg?style=for-the-badge" alt="Platform" />
  <img src="https://img.shields.io/badge/Core-Xray--core-orange.svg?style=for-the-badge" alt="Xray Core" />
  <img src="https://img.shields.io/badge/Channel-@Nzrmohammad-brightgreen.svg?style=for-the-badge&logo=telegram" alt="Telegram" />
</p>

<p align="center">
  <b>Fast, Modular, and Intelligent Clean-IP Scanner & Diagnostic Tool for VLESS and Xray-core.</b>
</p>

---

## 📖 Table of Contents
- [Key Features](#-key-features)
- [Results Preview](#-results-preview)
- [Project Architecture](#-project-architecture)
- [Prerequisites & Installation](#-prerequisites--installation)
- [Quick Start](#-quick-start)
- [Configuration Guide (`config.txt`)](#-configuration-guide-configtxt)
- [Speed Testing & Bandwidth Tuning Guide](#-speed-testing--bandwidth-tuning-guide)
- [Output Formats](#-output-formats)
- [Managing & Adding IP Ranges](#-managing--adding-ip-ranges)
- [Community & License](#-community--license)

---

## ⚡ Key Features

- **🚀 Ultra-Fast TCP Pre-filter**: Eliminates non-responsive IPs with high-concurrency non-blocking TCP handshakes before spawning proxy processes (up to 10x faster).
- **🔬 Real Xray-core Inbound Testing**: Measures genuine TLS handshakes and latency through temporary in-memory Xray SOCKS5 instances without modifying system proxy settings.
- **🌍 Physical IP Geo-Location (`IP Loc`)**: Automatically resolves and displays the genuine physical host location, city, and ASN of the clean/relay IP (e.g. `[IR] Tehran`, `[DE] Frankfurt`, `[US] Anycast`) using high-speed multi-threaded queries with thread-safe in-memory caching.
- **🏢 Cloudflare Edge PoP (`Colo`) Resolution**: Concurrently queries Cloudflare trace via the proxy tunnel to detect the exact Cloudflare edge termination airport code (e.g. `[NL] AMS`, `[TR] IST`, `[DE] FRA`).
- **🛡️ Anti-Drop / Longevity DPI Endurance Testing**: Evaluates connection endurance over sustained continuous traffic (30s continuous flow) to detect and filter out endpoints dropped or throttled by ISP DPI firewalls.
- **🌐 Full IPv4 & IPv6 Support**: Built-in support for official Cloudflare IPv6 clean ranges and subnets alongside classic IPv4 ranges.
- **📊 Jitter & Packet-Loss Stability Analysis**: Performs multi-sample ping evaluations (RFC 3393 / RFC 3550) to identify ultra-stable connections.
- **⚡ Real Speed Diagnostics**: Measures real **download** and **upload** throughput (`speed.cloudflare.com`) with warm-up TTFB isolation, adaptive payload sizing, and median-filtered multi-burst measurements.
- **🧠 Smart Use-Case Recommendations**: Automatically classifies and exports optimal endpoints tailored for:
  - 🛡️ **Anti-Drop**: 100% sustained connections resistant to censorship throttling.
  - 🎮 **Gaming**: Minimal packet loss, consistent ping, and lowest jitter.
  - 📱 **Streaming / Instagram**: Maximum download/upload bandwidth for videos and stories.
  - 🌐 **General Browsing**: Fast HTTP handshakes and high reliability.
- **🔄 Automated Core Downloader & Version Check**: Auto-detects official Xray binaries, checks for newer releases from GitHub, and reports core status on startup.
- **🎨 Cross-Platform Terminal UI**: Built with [Rich](https://github.com/Textualize/rich), featuring alternate-screen buffer (`Live`), keyboard navigation, interactive menus, and alignment-safe Unicode tables.
- **⚙️ 100% Config-Driven**: Set preferences once in `config.txt` and launch with zero interactive friction.
- **🗂️ Ready-to-Use Outputs**: Produces CSV reports (with GeoIP & Colo), TXT lists, per-port splits, and ready-to-import `vless://` URLs with location-tagged remarks (e.g. `#Gaming_IR_AMS`).

---

## 📊 Results Preview

When scanning finishes, endpoints are enriched with both physical host location (`IP Loc`) and Cloudflare edge data center (`Colo`):

```text
┌───┬──────────────┬──────┬─────────────┬──────────┬──────┬──────┬────────┬────────┬──────┬──────┬──────┬──────┐
│ # │ IP           │ Port │   IP Loc    │   Colo   │ Down │  Up  │  Ping  │ Jitter │ Loss │ Drop │ Pass │ HTTP │
├───┼──────────────┼──────┼─────────────┼──────────┼──────┼──────┼────────┼────────┼──────┼──────┼──────┼──────┤
│ 1 │ 62.60.195.74 │ 2087 │ [IR] Tehran │ [NL] AMS │ 7.1M │ 1.2M │ 1096ms │   43ms │   0% │ Pass │  5/5 │  204 │
│ 2 │ 46.38.148.65 │ 2087 │ [IR] Tehran │ [NL] AMS │ 9.9M │ 2.4M │ 1170ms │   67ms │   0% │ Pass │  5/5 │  204 │
│ 3 │ 104.16.1.1   │  443 │ [US] Anycast│ [TR] IST │  25M │ 8.5M │   42ms │    5ms │   0% │ Pass │  5/5 │  200 │
└───┴──────────────┴──────┴─────────────┴──────────┴──────┴──────┴────────┴────────┴──────┴──────┴──────┴──────┘
```

Smart recommendations are categorized and saved with ready-to-import VLESS links:

```text
┌─────────────┬───────────────────┬──────────┬────────────────────────────────┐
│ Use Case    │ Endpoint          │ Edge PoP │ Highlights & Performance       │
├─────────────┼───────────────────┼──────────┼────────────────────────────────┤
│ Gaming      │ 104.16.1.1:443    │ [TR] IST │ Ping: 42ms | Loss: 0% | Jitter │
│ Streaming   │ 104.16.1.1:443    │ [TR] IST │ Down: 25.00 Mbps | Anti-Drop   │
│ General Web │ 46.38.148.65:2087 │ [NL] AMS │ Ping: 1170ms | Port: 2087      │
│ Anti-Drop   │ 104.16.1.1:443    │ [TR] IST │ Sustained (0% drop) | Ping: 42 │
└─────────────┴───────────────────┴──────────┴────────────────────────────────┘
```

---

## 🏛 Project Architecture

Cloud Scanner follows a modular Object-Oriented Architecture:

```
Cloud_Scanner/
│
├── core/                       # Xray-core binary & routing assets (auto-downloaded)
│   ├── xray.exe / xray
│   ├── geoip.dat
│   └── geosite.dat
│
├── scanner/                    # Core Python Package
│   ├── __init__.py             # Package exports & version metadata
│   ├── constants.py            # Ports, URLs, Cloudflare Colo database & defaults
│   ├── models.py               # Strongly-typed Dataclasses & Custom Exceptions
│   ├── geoip.py                # GeoIPResolver: Physical host location & ASN resolution
│   ├── config.py               # ConfigManager: config.txt parser & auto-migration
│   ├── xray.py                 # XrayProcess (Context Manager) & version check
│   ├── targets.py              # CIDR/range expansion (IPv4 & IPv6)
│   ├── engine.py               # ScannerEngine: TCP filter, latency, anti-drop, speed
│   ├── analytics.py            # Result ranking & multi-criteria sorting
│   ├── storage.py              # ResultExporter: CSV, TXT, per-port, VLESS links
│   ├── logger.py               # File & console logging handler
│   ├── app.py                  # CloudScannerApp: Master CLI/TUI orchestrator
│   └── ui/                     # Terminal User Interface (TUI)
│       ├── __init__.py
│       ├── terminal.py         # Styling, alternate screen buffer, headers, prompts
│       ├── keys.py             # Cross-platform raw keyboard listener (Windows/POSIX)
│       ├── menus.py            # Flicker-free arrow-driven menus & multi-selectors
│       └── screens.py          # Startup check, summary tables, results
│
├── tests/                      # Automated pytest test suite (100% passing)
│   ├── test_analytics.py
│   ├── test_config.py
│   ├── test_engine.py
│   ├── test_geoip.py
│   ├── test_menus.py
│   ├── test_storage.py
│   ├── test_targets.py
│   └── test_xray.py
│
├── scripts/                    # Automation utilities
│   └── download_core.py        # Official cross-platform Xray-core downloader
│
├── ip-ranges/                  # Packaged clean IP ranges
│   ├── iran/                   # MCI, Irancell, Rightel, Shatel, Mokhaberat, etc.
│   ├── international/          # Hetzner, OVH, AWS, Fastly, etc.
│   └── ipv6/                   # Cloudflare Official IPv6 CIDRs & clean subnets
│
├── .github/workflows/ci.yml    # GitHub Actions multi-platform CI pipeline
├── pyproject.toml              # Project metadata, dev tools & test configuration
├── config.txt                  # User configuration file (untracked in git)
├── config.example.txt          # Clean template for git
├── requirements.txt            # Python dependencies (rich, requests)
├── .gitignore                  # Git exclusion rules
├── README.md                   # Project Documentation
└── main.py                     # Minimal entry-point script
```

---

## 📦 Prerequisites & Installation

1. **Python 3.10 or newer**: Ensure `python` is added to your system `PATH`.
2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *(For development and running tests: `pip install -e ".[dev]" && pytest tests/`)*
3. **Xray Core**: Automatically fetch official binaries into `core/`:
   ```bash
   python scripts/download_core.py
   ```
   *(Or place `xray.exe` / `xray` manually inside `core/` or the project root)*

---

## 🚀 Quick Start

### 1. Interactive Mode (Default)
Simply run:
```bash
python main.py
```
- The startup screen will verify that `xray.exe`, assets, and libraries are **FOUND** and display core version status.
- Press **Enter** to start scanning using your parameters in `config.txt`.
- Use **Up/Down Arrows** or numeric keys to select your target ISP range or custom file.

### 2. CLI Headless Mode (Automation & Servers)
Scan with explicit command-line arguments:
```bash
# Scan specific CIDR ranges on all 6 Cloudflare TLS ports
python main.py -c "vless://..." -t 104.16.0.0/16 104.17.0.0/16 --all-cf-tls-ports

# Scan Iranian ISP ranges with speed test and stability check
python main.py --isp-category iran --isp Irancell --recheck --speed-test
```

---

## ⚙️ Configuration Guide (`config.txt`)

You can edit `config.txt` to customize default behavior:

| Setting | Default | Description |
| :--- | :--- | :--- |
| `vless` | *(empty)* | Your complete `vless://...` configuration link. |
| `ports` | `443, 8443, 2053, 2083, 2087, 2096` | Ports to scan, or `config` to scan only the port in the link. |
| `workers` | `25` | Concurrency workers for scanning (optimized for socket stability). |
| `timeout` | `2` | Connection timeout in seconds. |
| `tcp_prefilter` | `true` | Ultra-fast TCP pre-filter handshake before Xray tests. |
| `max_targets` | `0` | Maximum target IPs to load (`0` = unlimited). |
| `post_scan_mode` | `full` | Post-scan quality testing: `full`, `stability`, `longevity`, `speed`, or `none`. |
| `top_targets` | `30` | Number of best-performing endpoints to test for speed/jitter (`0` or `all` = test ALL working IPs). |
| `ping_samples` | `8` | Pings per endpoint for stability (packet loss & RFC jitter). |
| `longevity_test` | `true` | Anti-Drop endurance test (sustained continuous streaming against DPI drops). |
| `longevity_duration` | `30` | Anti-Drop test duration in seconds (continuous stream). |
| `download_mb` | `5` | Download speed test size in megabytes (adaptively scaled based on warmup). |
| `upload_mb` | `1` | Upload speed test size in megabytes (`0` to skip). |
| `speed_duration` | `5` | Speed test timeout per IP in seconds. |
| `speed_workers` | `5` | Concurrency workers for speed testing. |

---

### ⚡ Speed Testing & Bandwidth Tuning Guide

Fine-tuning speed test parameters in `config.txt` depends directly on your connection bandwidth. The table below outlines recommended settings for different network speeds:

| Connection Type | Nominal Bandwidth | `download_mb` | `upload_mb` | `speed_duration` | `top_targets` | `speed_workers` | Notes & Recommendations |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **Standard ADSL / VDSL** | 8 – 24 Mbps *(~16M)* | `2` – `3` | `0` *(or `1`)* | `4` – `5` | `5` – `10` | `3` – `4` | Limited bandwidth; large test files cause timeouts. Upload test is best disabled (`0`) to prevent bufferbloat. |
| **4G / LTE / TD-LTE Mobile** | 40 – 100 Mbps | `5` – `10` | `1` – `2` | `5` | `10` | `5` | Balanced default profile; optimal for cellular modems and standard fiber lines. |
| **High-Speed FTTH / 5G / Fiber** | 200 – 400+ Mbps | `25` – `50` | `5` – `10` | `6` – `8` | `10` – `20` | `5` – `8` | Gigabit/fast connections require larger test chunks to ramp up TCP congestion window (CWND) and measure true throughput. |

---

### 💡 Technical Explanation & Best Practices:

1. **Why use smaller chunks (`download_mb = 2` to `3`) for 16 Mbps (ADSL)?**
   - 16 Mbps nominal downstream corresponds to a maximum real throughput of **~2 MB/s**.
   - If `download_mb` is set to 10 MB or 20 MB, testing each IP will take 5 to 10 full seconds, easily exceeding `speed_duration` timeouts and causing scans to take an excessive amount of time. A compact **2–3 MB** payload provides an accurate measurement within 1–2 seconds.
   - Upstream bandwidth on ADSL/VDSL is typically severely constrained (1–2 Mbps = ~120–250 KB/s). Running large upload tests will completely saturate the modem's transmit buffer (**bufferbloat**), generating artificial packet loss and disrupting overall home network connectivity. Therefore, setting `upload_mb = 0` (or `1`) is strongly recommended for ADSL.

2. **Why high-speed connections (300–400+ Mbps FTTH) need `download_mb = 25` to `50`:**
   - In TCP/IP networking, throughput does not immediately peak within the first few milliseconds due to the **TCP Slow-Start** algorithm, which gradually scales the Congestion Window (CWND).
   - If the test payload is too small (e.g. 2 MB or 5 MB), the entire download completes in less than 100 ms before the connection reaches its maximum steady-state rate. As a result, the measured speed might falsely appear as 60–80 Mbps instead of the actual 350+ Mbps.
   - For 300+ Mbps lines, setting `download_mb = 25` to `50` and `speed_duration = 6` to `8` allows the TCP stream to saturate the link and accurately capture peak throughput.

3. **Candidate Sample Size (`top_targets`):**
   - Defaults to `30`: after completing the initial latency scan, the engine sorts all responsive endpoints by lowest ping and runs speed and stability diagnostics on the top 30 candidates to conserve time and bandwidth.
   - Set to `0` or `all` if you want to perform speed tests on every single working IP discovered.

---

## 📁 Output Formats

All results, benchmarks, and configuration links are saved to the `results/` folder:

| File / Folder | Type | Description |
| :--- | :---: | :--- |
| **`scan_summary_report.txt`** | 📋 Summary | **Comprehensive All-In-One Report**: Human-readable diagnostic breakdown covering run metrics, candidate funnel stats (Target Candidates → TCP Alive → Working Xray), smart recommendations, and an aligned benchmark table with Latency, Jitter, Loss, Anti-Drop, Download/Upload speeds, and Cloudflare edge Colo. |
| **`recommended_configs.txt`** | 🔗 Links | **Curated Ready-to-Use VLESS Links**: Hand-picked configurations categorized for Gaming (lowest jitter/loss), Streaming (max bandwidth), Anti-Drop (100% steady continuous stream), and Balanced usage. |
| **`clean_ips_full_tested.txt`** | 📄 Text | **Deeply Benchmarked IP List**: Endpoints that successfully completed all post-scan stages (multi-ping stability, 30s DPI endurance, and speed benchmarks) with detailed metrics appended to each line. |
| **`clean_ips_full_tested_vless.txt`** | 🔗 Links | **Full-Tested VLESS Links**: Ready-to-import `vless://` URLs for all deeply tested endpoints, enriched with remark metrics (`#Remark-104.16.1.1:443-AMS_DL45M_UL12M_Ping42ms`). |
| **`clean_ips.txt`** | 📄 Text | **Initial Stage Working Endpoints**: Endpoints that passed the preliminary single-ping Xray TLS handshake. |
| **`clean_ips_vless.txt`** | 🔗 Links | **Initial Stage VLESS Links**: Ready-to-import `vless://` URLs generated from the initial latency scan with location tags. |
| **`clean_ips.csv`** | 📊 CSV | **Structured Dataset**: Full CSV report with dedicated columns (`ip`, `port`, `ip_country`, `ip_city`, `ip_org`, `ip_location`, `download_mbps`, `upload_mbps`, `avg_latency_ms`, `jitter_ms`, `packet_loss_pct`, `anti_drop_sustained`, `colo_code`, `colo_location`) for Excel, Google Sheets, or data pipelines. |
| **`tcp_alive_with_port.txt`** | 🔌 Socket | **TCP Pre-Filter Endpoints (`IP:Port`)**: Raw sockets that passed the high-concurrency non-blocking TCP handshake filter. |
| **`tcp_alive_ips.txt`** | 🌐 IP List | **TCP Pre-Filter Pure IPs**: Deduplicated list of clean IP addresses (without ports) that passed the TCP handshake. |
| **`by_port/`** | 📁 Directory | **Per-Port Output Directory**: Individual text files grouping working endpoints by specific port (e.g. `clean_ips_port_443.txt`, `clean_ips_port_8443.txt`, `clean_ips_port_2087.txt`). |

### Example Output Preview:

#### 1. Full-Tested Endpoints (`clean_ips_full_tested.txt`)
```text
# Cloud Scanner v0.3.0 - Full Tested Clean Endpoints
# Generated: 2026-10-16 18:00:00
104.16.1.1:443 | down: 45.20 Mbps | up: 12.30 Mbps | latency: 42.0 ms | jitter: 4.1 ms | loss: 0% | anti-drop: Pass | loc: [US] Anycast | colo: [TR] IST (Istanbul)
46.38.148.65:2087 | down: 9.90 Mbps | up: 3.20 Mbps | latency: 117.0 ms | jitter: 8.5 ms | loss: 0% | anti-drop: Pass | loc: [IR] Tehran | colo: [NL] AMS (Amsterdam)
```

#### 2. Comprehensive Scan Summary (`scan_summary_report.txt`)
```text
================================================================================
  CLOUD SCANNER 0.3.0 - COMPREHENSIVE SCAN SUMMARY REPORT
  Generated at: 2026-10-16 18:00:00  |  Telegram: @Nzrmohammad
================================================================================

1. CONFIGURATION & RUN METRICS
--------------------------------------------------------------------------------
  VLESS Remark : FastServer
  Target Server: my-subdomain.workers.dev:443
  Protocol     : ws | Security: tls

2. FUNNEL & HEALTH OVERVIEW
--------------------------------------------------------------------------------
  * Total Candidate Endpoints: 1524
  * TCP Pre-Filter Alive     : 68 (4.46% reachable)
  * Working Xray Proxies     : 60 (88.24% of alive)
  * Stage 3: Stability & Jitter recheck: 60 endpoints passed
  * Stage 4: Anti-Drop (DPI Endurance) : 58/60 sustained steady flow
  * Stage 5: Speed Benchmarks          : 30 tested (Top DL: 48.50 Mbps | Top UL: 14.20 Mbps)
```

---

## 🌐 Managing & Adding IP Ranges

Cloud Scanner features an automatic range discovery system:

### Directory Structure:
- **`ip-ranges/iran/`**: Iranian ISPs, Datacenters, and VPS Cloud Hosting providers (ArvanCloud, IranServer, Parspack, Mobinhost, Asiatech, etc.).
- **`ip-ranges/international/`**: Global Cloud & VPS providers (Gcore, Hetzner, OVH, DigitalOcean, Linode, Vultr, Leaseweb, Netcup, etc.).
- **`ip-ranges/ipv6/`**: Cloudflare Official IPv6 CIDRs and clean subnets.

### How to Add a New Provider / Range:
1. Create a new `.txt` file inside the appropriate directory (`ip-ranges/iran/` or `ip-ranges/international/`). The file name will automatically become the menu item name (e.g., `MyCustomHost.txt`).
2. Inside the file, add your IP targets, one per line. The following formats are supported:
   - **CIDR Subnets**: `185.14.160.0/24` or `2606:4700::/32`
   - **IP Ranges**: `1.1.1.1-1.1.1.50`
   - **Single IPs**: `104.16.1.1`
   - **Endpoints with Ports**: `104.16.1.1:443`
3. Save the file. Run `python main.py` and navigate to **Target Source -> ISP range list**. Your new provider will appear instantly!

### How to Edit or Remove:
- **To edit**: Simply open any existing `.txt` file, add or remove subnets, and save.
- **To remove**: Delete the `.txt` file from the directory, and it will immediately disappear from the menu.

---

## 👨‍💻 Community & License

- **Author**: Mohammad
- **Telegram Channel**: [@Nzrmohammad](https://t.me/Nzrmohammad)
- **License**: [MIT License](LICENSE)
