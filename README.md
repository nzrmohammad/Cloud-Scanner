# 🌐 Cloud Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+" />
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
- [Output Formats](#-output-formats)
- [Community & License](#-community--license)

---

## ⚡ Key Features

- **🚀 Ultra-Fast TCP Pre-filter**: Eliminates non-responsive IPs with high-concurrency non-blocking TCP handshakes before spawning proxy processes (up to 10x faster).
- **🔬 Real Xray-core Inbound Testing**: Measures genuine TLS handshakes and latency through temporary in-memory Xray SOCKS5 instances without modifying system proxy settings.
- **🌍 Physical IP Geo-Location (`IP Loc`)**: Automatically resolves and displays the genuine physical host location, city, and ASN of the clean/relay IP (e.g. `[IR] Tehran`, `[DE] Frankfurt`, `[US] Anycast`) using high-speed multi-threaded queries with thread-safe in-memory caching.
- **🏢 Cloudflare Edge PoP (`Colo`) Resolution**: Concurrently queries Cloudflare trace via the proxy tunnel to detect the exact Cloudflare edge termination airport code (e.g. `[NL] AMS`, `[TR] IST`, `[DE] FRA`).
- **🛡️ Anti-Drop / Longevity DPI Endurance Testing**: Evaluates connection endurance over sustained continuous traffic (15–20s) to detect and filter out endpoints dropped or throttled by ISP DPI firewalls.
- **🌐 Full IPv4 & IPv6 Support**: Built-in support for official Cloudflare IPv6 clean ranges and subnets alongside classic IPv4 ranges.
- **📊 Jitter & Packet-Loss Stability Analysis**: Performs multi-sample ping evaluations to identify ultra-stable connections.
- **⚡ Real Speed Diagnostics**: Measures real **download** and **upload** throughput (`speed.cloudflare.com`) in Mbps.
- **🧠 Smart Use-Case Recommendations**: Automatically classifies and exports optimal endpoints tailored for:
  - 🛡️ **Anti-Drop**: 100% sustained connections resistant to censorship throttling.
  - 🎮 **Gaming**: Minimal packet loss, consistent ping, and lowest jitter.
  - 📱 **Streaming / Instagram**: Maximum download/upload bandwidth for videos and stories.
  - 🌐 **General Browsing**: Fast HTTP handshakes and high reliability.
- **🔄 Automated Core Downloader & Version Check**: Auto-detects official Xray binaries, checks for newer releases from GitHub, and reports core status on startup.
- **🎨 Cross-Platform Terminal UI**: Built with [Rich](https://github.com/Textualize/rich), featuring keyboard navigation, interactive menus, and alignment-safe Unicode tables.
- **⚙️ 100% Config-Driven**: Set preferences once in `config.txt` and launch with zero interactive friction.
- **🗂️ Ready-to-Use Outputs**: Produces CSV reports (with GeoIP & Colo), TXT lists, per-port splits, and ready-to-import `vless://` URLs with location-tagged remarks (e.g. `#Gaming_IR_AMS`).

---

## 📊 Results Preview

When scanning finishes, endpoints are enriched with both physical host location (`IP Loc`) and Cloudflare edge data center (`Colo`):

```text
┌───┬──────────────┬──────┬─────────────┬──────────┬──────┬─────────┬────────┬──────┬──────────┬──────┬──────┐
│ # │ IP           │ Port │   IP Loc    │   Colo   │ Down │ Latency │ Jitter │ Loss │ AntiDrop │ Pass │ HTTP │
├───┼──────────────┼──────┼─────────────┼──────────┼──────┼─────────┼────────┼──────┼──────────┼──────┼──────┤
│ 1 │ 62.60.195.74 │ 2087 │ [IR] Tehran │ [NL] AMS │ 7.1M │  1096ms │   43ms │   0% │   Pass   │  5/5 │  204 │
│ 2 │ 46.38.148.65 │ 2087 │ [IR] Tehran │ [NL] AMS │ 9.9M │  1170ms │   67ms │   0% │   Pass   │  5/5 │  204 │
│ 3 │ 104.16.1.1   │  443 │ [US] Anycast│ [TR] IST │  25M │    42ms │    5ms │   0% │   Pass   │  5/5 │  200 │
└───┴──────────────┴──────┴─────────────┴──────────┴──────┴─────────┴────────┴──────┴──────────┴──────┴──────┘
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
│   ├── config.py               # ConfigManager: config.txt parser & in-place updater
│   ├── xray.py                 # XrayProcess (Context Manager) & version check
│   ├── targets.py              # TargetResolver: CIDR/range expansion (IPv4 & IPv6)
│   ├── engine.py               # ScannerEngine: TCP filter, latency, anti-drop, speed
│   ├── analytics.py            # RecommendationEngine & multi-criteria sorting
│   ├── storage.py              # ResultExporter: CSV, TXT, per-port, VLESS links
│   ├── app.py                  # CloudScannerApp: Master CLI/TUI orchestrator
│   └── ui/                     # Terminal User Interface (TUI)
│       ├── __init__.py
│       ├── terminal.py         # Styling, banners, stages, prompts
│       ├── keys.py             # Cross-platform raw keyboard listener (Windows/POSIX)
│       ├── menus.py            # Arrow-driven key menus & multi-selectors
│       └── screens.py          # Startup check, summary tables, results
│
├── scripts/                    # Automation utilities
│   └── download_core.py        # Official cross-platform Xray-core downloader
│
├── ip-ranges/                  # Packaged clean IP ranges
│   ├── iran/                   # MCI, Irancell, Rightel, Shatel, Mokhaberat, etc.
│   ├── international/          # Hetzner, OVH, AWS, Fastly, etc.
│   └── ipv6/                   # Cloudflare Official IPv6 CIDRs & clean subnets
│
├── config.txt                  # User configuration file (untracked in git)
├── config.example.txt          # Clean template for git
├── requirements.txt            # Python dependencies (rich, requests)
├── .gitignore                  # Git exclusion rules
├── README.md                   # Project Documentation
└── main.py                     # Minimal entry-point script
```

---

## 📦 Prerequisites & Installation

1. **Python 3.9 or newer**: Ensure `python` is added to your system `PATH`.
2. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
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
| `workers` | `66` | Concurrency workers for scanning. |
| `timeout` | `2` | Connection timeout in seconds. |
| `tcp_prefilter` | `true` | Ultra-fast TCP pre-filter handshake before Xray tests. |
| `max_targets` | `0` | Maximum target IPs to load (`0` = unlimited). |
| `post_scan_mode` | `full` | Post-scan quality testing: `full`, `stability`, `longevity`, `speed`, or `none`. |
| `top_targets` | `10` | Number of best-performing endpoints to test for speed/jitter (`0` or `all` = test ALL working IPs). |
| `ping_samples` | `5` | Pings per endpoint for stability (packet loss & jitter). |
| `longevity_test` | `true` | Anti-Drop endurance test (sustained traffic against DPI drops). |
| `longevity_duration` | `15` | Anti-Drop test duration in seconds. |
| `download_mb` | `5` | Download speed test size in megabytes. |
| `upload_mb` | `1` | Upload speed test size in megabytes (`0` to skip). |
| `speed_duration` | `5` | Speed test timeout per IP in seconds. |

---

## 📁 Output Formats

Results are saved to the `results/` folder:
- **`clean_ips.csv`**: Comprehensive CSV reports with dedicated columns: `ip`, `port`, `ip_country`, `ip_city`, `ip_org`, `ip_location`, `download_mbps`, `upload_mbps`, `avg_latency_ms`, `jitter_ms`, `packet_loss_pct`, `anti_drop_sustained`, `colo_code`, `colo_location`.
- **`clean_ips.txt`**: Clean text format listing working endpoints with physical location and edge PoP:
  `62.60.195.74:2087 | down: 7.10 Mbps | latency: 1096.0 ms | loc: [IR] Tehran | colo: [NL] AMS (Amsterdam) | HTTP 204`
- **`clean_ips_vless.txt`**: Ready-to-import `vless://` links formatted with location-aware remarks:
  `vless://...?host=...#MyRemark-62.60.195.74:2087-IR_AMS_7.1M_AntiDrop`
- **`recommended_configs.txt`**: Curated configurations recommended specifically for Anti-Drop, Gaming, Streaming, and Browsing.
- **`by_port/`**: Separate result files grouped by port (e.g. `clean_ips_port_443.txt`, `clean_ips_port_2087.txt`).

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
