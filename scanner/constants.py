from pathlib import Path
import sys

APP_NAME = "Cloud Scanner"
APP_VERSION = "v0.2.0"
APP_CHANNEL = "@Nzrmohammad"
APP_URL = "https://t.me/Nzrmohammad"
APP_HEADER = f"{APP_NAME} {APP_VERSION} | {APP_CHANNEL}"

DEFAULT_CF_TLS_PORTS = (443, 8443, 2053, 2083, 2087, 2096)
DEFAULT_CONCURRENCY = 66
DEFAULT_TIMEOUT = 2
DEFAULT_TRIES = 1
MAX_DEFAULT_HOSTS = 0

DEFAULT_URL = "https://www.gstatic.com/generate_204"
DEFAULT_SPEED_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"
DEFAULT_UPLOAD_URL = "https://speed.cloudflare.com/__up"
DEFAULT_SPEED_BYTES = 5 * 1024 * 1024
DEFAULT_UPLOAD_BYTES = 1 * 1024 * 1024
DEFAULT_LONGEVITY_DURATION = 15

LATENCY_TEST_URLS = [
    ("Google generate_204", "https://www.gstatic.com/generate_204", "Fast & globally reliable (Recommended)"),
    ("Cloudflare trace", "https://cloudflare.com/cdn-cgi/trace", "Direct Cloudflare edge diagnostic"),
    ("Cloudflare 204", "https://cp.cloudflare.com/generate_204", "Cloudflare captive portal endpoint"),
]

ISP_CATEGORIES = {
    "iran": "Iranian ISPs & Datacenters",
    "international": "International ISPs & Clouds",
    "ipv6": "IPv6 Ranges (Cloudflare & Clouds)",
}

DEFAULT_CONFIG_FILENAME = "config.txt"

CF_TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"

# Comprehensive Cloudflare Edge PoP / Airport Code mapping
# Maps 3-letter IATA airport codes to (Country Code, City Name)
CF_COLO_LOCATIONS = {
    # Middle East & Nearby Iran
    "IST": ("TR", "Istanbul"),
    "SAW": ("TR", "Istanbul Sabiha"),
    "AYT": ("TR", "Antalya"),
    "ADB": ("TR", "Izmir"),
    "ESB": ("TR", "Ankara"),
    "DXB": ("AE", "Dubai"),
    "DWC": ("AE", "Dubai World"),
    "AUH": ("AE", "Abu Dhabi"),
    "DOH": ("QA", "Doha"),
    "BAH": ("BH", "Manama"),
    "KWI": ("KW", "Kuwait City"),
    "MCT": ("OM", "Muscat"),
    "RUH": ("SA", "Riyadh"),
    "JED": ("SA", "Jeddah"),
    "DMM": ("SA", "Dammam"),
    "MED": ("SA", "Medina"),
    "BGW": ("IQ", "Baghdad"),
    "BSR": ("IQ", "Basra"),
    "EBL": ("IQ", "Erbil"),
    "EVN": ("AM", "Yerevan"),
    "TBS": ("GE", "Tbilisi"),
    "BAK": ("AZ", "Baku"),
    "AMM": ("JO", "Amman"),
    "BEY": ("LB", "Beirut"),
    "TLV": ("IL", "Tel Aviv"),
    "KBL": ("AF", "Kabul"),
    "ISB": ("PK", "Islamabad"),
    "KHI": ("PK", "Karachi"),
    "LHE": ("PK", "Lahore"),
    "TAS": ("UZ", "Tashkent"),
    "ALA": ("KZ", "Almaty"),
    "TSE": ("KZ", "Astana"),
    "ASB": ("TM", "Ashgabat"),
    # Europe
    "FRA": ("DE", "Frankfurt"),
    "MUC": ("DE", "Munich"),
    "BER": ("DE", "Berlin"),
    "DUS": ("DE", "Dusseldorf"),
    "HAM": ("DE", "Hamburg"),
    "STR": ("DE", "Stuttgart"),
    "AMS": ("NL", "Amsterdam"),
    "LHR": ("GB", "London Heathrow"),
    "LGW": ("GB", "London Gatwick"),
    "MAN": ("GB", "Manchester"),
    "CDG": ("FR", "Paris"),
    "MRS": ("FR", "Marseille"),
    "LYS": ("FR", "Lyon"),
    "MXP": ("IT", "Milan"),
    "FCO": ("IT", "Rome"),
    "MAD": ("ES", "Madrid"),
    "BCN": ("ES", "Barcelona"),
    "LIS": ("PT", "Lisbon"),
    "VIE": ("AT", "Vienna"),
    "ZRH": ("CH", "Zurich"),
    "GVA": ("CH", "Geneva"),
    "BRU": ("BE", "Brussels"),
    "WAW": ("PL", "Warsaw"),
    "PRG": ("CZ", "Prague"),
    "BUD": ("HU", "Budapest"),
    "OTP": ("RO", "Bucharest"),
    "SOF": ("BG", "Sofia"),
    "ATH": ("GR", "Athens"),
    "SKG": ("GR", "Thessaloniki"),
    "BEG": ("RS", "Belgrade"),
    "ZAG": ("HR", "Zagreb"),
    "KIV": ("MD", "Chisinau"),
    "HEL": ("FI", "Helsinki"),
    "ARN": ("SE", "Stockholm"),
    "CPH": ("DK", "Copenhagen"),
    "OSL": ("NO", "Oslo"),
    "DUB": ("IE", "Dublin"),
    "TLL": ("EE", "Tallinn"),
    "RIX": ("LV", "Riga"),
    "VNO": ("LT", "Vilnius"),
    "LCY": ("GB", "London City"),
    "DME": ("RU", "Moscow"),
    "SVO": ("RU", "Moscow"),
    "LED": ("RU", "Saint Petersburg"),
    "KBP": ("UA", "Kyiv"),
    # Asia & Oceania
    "SIN": ("SG", "Singapore"),
    "HKG": ("HK", "Hong Kong"),
    "NRT": ("JP", "Tokyo Narita"),
    "HND": ("JP", "Tokyo Haneda"),
    "KIX": ("JP", "Osaka"),
    "ICN": ("KR", "Seoul"),
    "TPE": ("TW", "Taipei"),
    "BKK": ("TH", "Bangkok"),
    "KUL": ("MY", "Kuala Lumpur"),
    "JKT": ("ID", "Jakarta"),
    "MNL": ("PH", "Manila"),
    "SGN": ("VN", "Ho Chi Minh"),
    "HAN": ("VN", "Hanoi"),
    "DEL": ("IN", "New Delhi"),
    "BOM": ("IN", "Mumbai"),
    "BLR": ("IN", "Bangalore"),
    "MAA": ("IN", "Chennai"),
    "HYD": ("IN", "Hyderabad"),
    "CMB": ("LK", "Colombo"),
    "SYD": ("AU", "Sydney"),
    "MEL": ("AU", "Melbourne"),
    "AKL": ("NZ", "Auckland"),
    # Americas
    "IAD": ("US", "Ashburn / DC"),
    "JFK": ("US", "New York"),
    "EWR": ("US", "Newark"),
    "ORD": ("US", "Chicago"),
    "SFO": ("US", "San Francisco"),
    "SJC": ("US", "San Jose"),
    "LAX": ("US", "Los Angeles"),
    "SEA": ("US", "Seattle"),
    "MIA": ("US", "Miami"),
    "DFW": ("US", "Dallas"),
    "ATL": ("US", "Atlanta"),
    "DEN": ("US", "Denver"),
    "YYZ": ("CA", "Toronto"),
    "YUL": ("CA", "Montreal"),
    "YVR": ("CA", "Vancouver"),
    "GRU": ("BR", "Sao Paulo"),
    "EZE": ("AR", "Buenos Aires"),
    "SCL": ("CL", "Santiago"),
    "BOG": ("CO", "Bogota"),
    # Africa
    "JNB": ("ZA", "Johannesburg"),
    "CPT": ("ZA", "Cape Town"),
    "CAI": ("EG", "Cairo"),
    "LOS": ("NG", "Lagos"),
    "NBO": ("KE", "Nairobi"),
}


def parse_cf_colo(trace_body: str) -> Optional[str]:
    """Parse Cloudflare 3-letter IATA colo code from cdn-cgi/trace output."""
    if not trace_body:
        return None
    for line in trace_body.splitlines():
        line = line.strip()
        if line.startswith("colo="):
            colo = line.split("=", 1)[1].strip().upper()
            if colo:
                return colo
    return None


def format_cf_colo(colo_code: Optional[str], short: bool = False) -> str:
    """Format a 3-letter Cloudflare colo code into a clean, terminal-safe location string.

    Examples:
        format_cf_colo("IST") -> "[TR] IST (Istanbul)"
        format_cf_colo("IST", short=True) -> "[TR] IST"
        format_cf_colo("XYZ") -> "XYZ"
    """
    if not colo_code:
        return "" if short else "-"
    code = colo_code.strip().upper()
    info = CF_COLO_LOCATIONS.get(code)
    if not info:
        return code
    country, city = info
    if short:
        return f"[{country}] {code}"
    return f"[{country}] {code} ({city})"

DEFAULT_CONFIG_TEMPLATE = """# ==============================================================
# Cloud Scanner Settings (تنظیمات اسکنر کلودفلر)
# ==============================================================

# VLESS Config Link (لینک کانفیگ)
vless = {vless}

# Target Ports to scan (پورت‌های مورد نظر برای اسکن - جدا شده با کاما)
# برای اسکن ۶ پورت اصلی کلودفلر: 443, 8443, 2053, 2083, 2087, 2096
# برای اسکن فقط پورت داخل کانفیگ: config
ports = 443, 8443, 2053, 2083, 2087, 2096

# Scan Speed / Workers (سرعت اسکن / تعداد ورکرها)
workers = 66

# Timeout in seconds (مهلت اتصال به ثانیه)
timeout = 2

# Fast TCP Pre-filter (پیش‌فیلتر فوق سریع TCP)
tcp_prefilter = true

# Latency Test URL (آدرس تست پینگ و اتصال)
test_url = https://www.gstatic.com/generate_204

# Maximum target IPs to load/scan (حداکثر تعداد آی‌پی برای اسکن)
# عدد 0 یا unlimited یعنی تمام آی‌پی‌ها بدون محدودیت اسکن شوند؛ یا یک عدد دلخواه (مثلاً 500 یا 1000)
max_targets = 0

# ==============================================================
# Quality, Anti-Drop & Speed Testing (تنظیمات تست کیفیت، عدم قطع و سرعت)
# ==============================================================
# Post-scan test mode: full | stability | longevity | speed | none
# full: Stability + Anti-Drop (DPI Endurance) + Download & Upload Speed
# stability: Stability (Loss% + Jitter) only
# longevity: Anti-Drop Endurance test only
# speed: Download & Upload Speed only
# none: Skip post-scan testing
post_scan_mode = full

# Top targets count to test for quality & speed (تعداد برترین اهداف جهت تست سرعت و پایداری)
# عدد 0 یا all یعنی تمام آی‌پی‌های سالم پیدا شده تست شوند؛ یا یک عدد (مثلاً 10 یا 20) برای گلچین برترین‌ها بر اساس کمترین پینگ
top_targets = 10

# Ping samples for stability & jitter test (تعداد پینگ تست پایداری و جیتر)
ping_samples = 5

# Anti-Drop / Longevity endurance test (تست مقاومت در برابر قطع شدن توسط فیلترینگ DPI)
# بررسی زنده ماندن اتصال در طول زمان و عدم ارسال پکت‌های قطع اتصال (TCP RST)
longevity_test = true

# Longevity test duration in seconds (مدت زمان تست پایداری مداوم به ثانیه)
longevity_duration = 15

# Download test size in MB (حجم فایل دانلود تستی بر حسب مگابایت)
download_mb = 5

# Upload test size in MB (حجم فایل آپلود تستی بر حسب مگابایت - عدد 0 یعنی غیرفعال)
upload_mb = 1

# Max test duration per IP in seconds (محدودیت زمان تست سرعت)
speed_duration = 5
"""


def app_dir() -> Path:
    """Return the base directory of the project."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    # Return root directory (parent of scanner package)
    return Path(__file__).resolve().parent.parent


def isp_root() -> Path:
    """Return the path to ip-ranges directory."""
    base = app_dir()
    for candidate in [base / "ip-ranges", base / "isps"]:
        if candidate.exists() and candidate.is_dir():
            return candidate
    return base / "ip-ranges"
