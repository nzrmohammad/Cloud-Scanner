from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
from scanner.constants import app_dir, DEFAULT_URL


@dataclass
class VlessConfig:
    raw: str = ""
    uuid: str = ""
    host: str = ""
    port: int = 443
    remark: str = ""
    query: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    ip: str
    ok: bool = False
    port: int = 443
    latency_ms: Optional[float] = None
    status_code: Optional[int] = None
    error: str = ""
    speed_mbps: Optional[float] = None
    speed_bytes: int = 0
    speed_error: str = ""
    upload_mbps: Optional[float] = None
    upload_bytes: int = 0
    upload_error: str = ""
    recheck_passed: int = 0
    recheck_total: int = 0
    packet_loss: float = 0.0
    jitter_ms: Optional[float] = None
    sustained: Optional[bool] = None
    longevity_loss: Optional[float] = None
    colo: Optional[str] = None
    ip_country: Optional[str] = None
    ip_city: Optional[str] = None
    ip_org: Optional[str] = None

    @property
    def endpoint(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True)
class TargetSource:
    start: int
    end: int
    version: int
    label: str = ""

    @property
    def size(self) -> int:
        return max(0, self.end - self.start + 1)


@dataclass
class AppSettings:
    vless_raw: str = ""
    ports: List[int] = field(default_factory=lambda: [443, 8443, 2053, 2083, 2087, 2096])
    workers: int = 66
    timeout: int = 2
    tcp_prefilter: bool = True
    test_url: str = DEFAULT_URL
    max_targets: int = 0  # 0 = unlimited
    output_dir: Path = field(default_factory=lambda: app_dir() / "results")
    post_scan_mode: str = "full"  # full, stability, speed, longevity, none
    top_targets: int = 10
    ping_samples: int = 5
    longevity_test: bool = True
    longevity_duration: int = 15
    download_mb: int = 5
    upload_mb: int = 1
    speed_duration: int = 5
    speed_workers: int = 5


@dataclass
class SmartRecommendation:
    category: str
    icon: str
    result: ScanResult
    reason: str
    vless_link: str = ""


class NavigationBack(Exception):
    """Raised internally when the user asks to step back in the TUI."""
    pass


class NavigationExit(Exception):
    """Raised internally when the user asks to exit from the TUI."""
    pass


class ScanInterrupted(Exception):
    """Raised when Ctrl+C interrupts a scan-like stage after partial results exist."""

    def __init__(self, results: List[ScanResult], stage: str = "scan") -> None:
        super().__init__(f"Interrupted during {stage}")
        self.results = results
        self.stage = stage
