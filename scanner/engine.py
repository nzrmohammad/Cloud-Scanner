from __future__ import annotations

import random
import socket
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple, TypeVar

from scanner.analytics import (
    full_sort_key,
    latency_sort_key,
    longevity_sort_key,
    recheck_sort_key,
    speed_sort_key,
)
from scanner.constants import (
    APP_HEADER,
    CF_TRACE_URL,
    DEFAULT_CONCURRENCY,
    DEFAULT_LONGEVITY_DURATION,
    DEFAULT_SPEED_BYTES,
    DEFAULT_SPEED_URL,
    DEFAULT_TIMEOUT,
    DEFAULT_TRIES,
    DEFAULT_UPLOAD_BYTES,
    DEFAULT_UPLOAD_URL,
    DEFAULT_URL,
    app_dir,
    mb_to_bytes,
    parse_cf_colo,
)
from scanner.geoip import enrich_results_with_geoip
from scanner.logger import get_logger
from scanner.models import (
    AppSettings,
    ScanInterrupted,
    ScanResult,
    VlessConfig,
)
from scanner.storage import save_results
from scanner.targets import parse_ip_and_port
from scanner.xray import BatchXrayProcess, XrayProcess

logger = get_logger("engine")

try:
    import requests
except ImportError:
    requests = None


T = TypeVar("T")
R = TypeVar("R")


class DaemonThreadPoolExecutor(ThreadPoolExecutor):
    """ThreadPoolExecutor whose worker threads are daemon threads so Ctrl+C / process exit never hangs."""

    def _adjust_thread_count(self) -> None:
        cur = threading.current_thread()
        old_daemonic = getattr(cur, "_daemonic", False)
        try:
            cur._daemonic = True  # type: ignore[attr-defined]
            super()._adjust_thread_count()
        finally:
            cur._daemonic = old_daemonic  # type: ignore[attr-defined]


def _run_concurrent_tasks(
    items: List[T],
    task_fn: Callable[[T], R],
    workers: int,
    stage_name: str,
    on_result: Optional[Callable[[R, int, int], None]] = None,
    abort_event: Optional[threading.Event] = None,
) -> List[R]:
    """Execute task_fn concurrently across items with KeyboardInterrupt cancellation.

    Adheres strictly to DRY principles by centralizing ThreadPoolExecutor management,
    as_completed processing, error logging, and graceful ScanInterrupted raising.
    """
    if not items:
        return []

    results: List[R] = []
    ex = DaemonThreadPoolExecutor(max_workers=max(1, workers))
    futures = {}
    try:
        futures = {ex.submit(task_fn, item): item for item in items}
        done = 0
        total = len(items)
        for fut in as_completed(futures):
            try:
                res = fut.result()
            except Exception as exc:
                logger.error("Unhandled exception in %s task: %s", stage_name, exc, exc_info=True)
                continue
            results.append(res)
            done += 1
            if on_result:
                try:
                    on_result(res, done, total)
                except Exception as exc:
                    logger.debug("on_result callback error in %s: %s", stage_name, exc)
    except KeyboardInterrupt as exc:
        if abort_event is not None:
            abort_event.set()
        logger.warning("KeyboardInterrupt received in %s, canceling %d futures", stage_name, len(futures))
        for fut in futures:
            fut.cancel()
        ex.shutdown(wait=False, cancel_futures=True)
        raise ScanInterrupted(results, stage_name) from exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)

    return results


def check_tcp_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Fast TCP connection check. Returns True if TCP handshake succeeds."""
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except (socket.timeout, OSError):
        return False


def fast_tcp_filter(
    target_pairs: List[Tuple[str, int]],
    timeout: float = 1.0,
    workers: int = 30,
    on_progress: Optional[Callable[[int, int, int], None]] = None,
) -> List[Tuple[str, int]]:
    """Filter candidate endpoints using fast TCP handshake before running Xray."""
    alive: List[Tuple[str, int]] = []
    total = len(target_pairs)
    if total == 0:
        return []
    max_w = min(workers, total, 30)
    done = 0
    with ThreadPoolExecutor(max_workers=max_w) as ex:
        futures = {ex.submit(check_tcp_port, ip, port, timeout): (ip, port) for ip, port in target_pairs}
        for fut in as_completed(futures):
            pair = futures[fut]
            try:
                if fut.result():
                    alive.append(pair)
            except Exception as exc:
                logger.debug("TCP prefilter error for %s:%d: %s", pair[0], pair[1], exc)
            done += 1
            if on_progress:
                try:
                    on_progress(done, total, len(alive))
                except Exception as exc:
                    logger.debug("Prefilter on_progress error: %s", exc)
    return alive


def save_tcp_alive_endpoints(
    alive_endpoints: List[Tuple[str, int]],
    output_dir: Optional[Path] = None,
) -> Tuple[Path, Path]:
    """Save TCP-prefiltered alive endpoints (IP:port) and unique IPs to files."""
    if output_dir is None:
        output_dir = app_dir() / "results"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    tcp_alive_file = output_dir / "tcp_alive.txt"
    tcp_ips_file = output_dir / "tcp_alive_ips.txt"

    endpoint_lines = [f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}" for ip, port in alive_endpoints]
    tcp_alive_file.write_text("\n".join(endpoint_lines) + "\n", encoding="utf-8")

    unique_ips = list(dict.fromkeys(ip for ip, _ in alive_endpoints))
    tcp_ips_file.write_text("\n".join(unique_ips) + "\n", encoding="utf-8")

    return tcp_alive_file, tcp_ips_file


def test_ip(
    v: VlessConfig,
    ip: str,
    port: int,
    xray: Path,
    timeout: int,
    tries: int,
    url: str,
    loglevel: str = "warning",
) -> ScanResult:
    """Test a single IP and port through Xray's local SOCKS proxy."""
    if requests is None:
        return ScanResult(ip=ip, port=port, ok=False, error="Python package requests[socks] is not installed")

    last_error = ""
    for _ in range(max(1, tries)):
        try:
            start = time.perf_counter()
            with XrayProcess(xray, v, ip, port, loglevel=loglevel, ready_timeout=min(3.0, float(timeout))) as xp:
                r = requests.get(url, proxies=xp.proxies, timeout=timeout, headers={"User-Agent": APP_HEADER})
                latency = (time.perf_counter() - start) * 1000
                if 200 <= r.status_code < 400:
                    colo = parse_cf_colo(r.text[:500]) if (r.text and "colo=" in r.text[:500]) else None
                    return ScanResult(ip=ip, port=port, ok=True, latency_ms=latency, status_code=r.status_code, colo=colo)
                last_error = f"HTTP {r.status_code}"
        except TimeoutError:
            last_error = "Xray SOCKS port did not start"
        except Exception as exc:
            logger.debug("test_ip request failed for %s:%d: %s", ip, port, exc)
            last_error = str(exc).split("\n", 1)[0][:160]
    return ScanResult(ip=ip, port=port, ok=False, error=last_error or "Failed")


class StreamUploadPayload:
    """Zero-RAM streaming upload payload that isolates TLS/TCP setup from data transfer timing."""

    def __init__(self, size: int, chunk_size: int = 64 * 1024):
        self.size = size
        self.chunk_size = chunk_size
        self.bytes_sent = 0
        self.transfer_start: Optional[float] = None
        self.transfer_end: Optional[float] = None
        self._buffer = b"\x00" * min(self.chunk_size, max(1, self.size))

    def __iter__(self):
        while self.bytes_sent < self.size:
            if self.transfer_start is None:
                self.transfer_start = time.perf_counter()
            to_send = min(len(self._buffer), self.size - self.bytes_sent)
            self.bytes_sent += to_send
            yield self._buffer[:to_send]
        self.transfer_end = time.perf_counter()

    def __len__(self) -> int:
        return self.size


def speed_test_ip(
    v: VlessConfig,
    base_result: ScanResult,
    xray: Path,
    timeout: int,
    speed_bytes: int,
    speed_duration: int,
    speed_url_template: str,
    loglevel: str = "warning",
    test_upload: bool = True,
    upload_bytes: int = DEFAULT_UPLOAD_BYTES,
    upload_url: str = DEFAULT_UPLOAD_URL,
) -> ScanResult:
    """Run real download and upload speed tests through Xray for one working endpoint."""
    ip = base_result.ip
    port = base_result.port
    out = replace(base_result)

    if requests is None:
        out.speed_error = "Python package requests[socks] is not installed"
        return out

    try:
        with XrayProcess(xray, v, ip, port, loglevel=loglevel, ready_timeout=min(3.0, float(timeout))) as xp:
            proxies = xp.proxies

            # 1. Download Speed Test with Warmup, TTFB isolation, Adaptive Sizing & Median Filtering
            if speed_bytes > 0:
                warmup_size = min(speed_bytes, mb_to_bytes(1) // 4)
                warmup_url = speed_url_template.format(bytes=warmup_size)
                preliminary_mbps: Optional[float] = None

                # Warmup phase: establishes TCP window size, isolates TTFB, measures preliminary throughput
                try:
                    w_req_start = time.perf_counter()
                    with requests.get(
                        warmup_url,
                        proxies=proxies,
                        timeout=min(3.0, float(timeout)),
                        stream=True,
                        headers={"User-Agent": APP_HEADER},
                    ) as w:
                        ttfb = (time.perf_counter() - w_req_start) * 1000.0
                        out.ttfb_ms = round(ttfb, 1)

                        w_downloaded = 0
                        w_transfer_start = time.perf_counter()
                        for chunk in w.iter_content(chunk_size=64 * 1024):
                            if not chunk:
                                break
                            w_downloaded += len(chunk)
                        w_elapsed = time.perf_counter() - w_transfer_start
                        if w_elapsed > 0.02 and w_downloaded > 0:
                            preliminary_mbps = (w_downloaded * 8) / (w_elapsed * 1_000_000)
                except Exception as exc:
                    logger.debug("Warmup error for %s: %s", out.endpoint, exc)

                # Adaptive payload sizing based on preliminary throughput:
                # - Very slow (< 20 Mbps): shrink to ~2 MB so test finishes promptly without socket timeout
                # - Very fast (> 100 Mbps): expand to ~20 MB to properly saturate high-BDP pipe
                # - Normal (20..100 Mbps): maintain configured speed_bytes (typically 5 MB)
                target_bytes = speed_bytes
                if preliminary_mbps is not None:
                    if preliminary_mbps < 20.0:
                        target_bytes = min(speed_bytes, mb_to_bytes(2))
                    elif preliminary_mbps > 100.0:
                        target_bytes = max(speed_bytes, mb_to_bytes(20))

                # Multi-burst measurement: run 2-3 iterations taking the median to filter network jitter
                num_bursts = 3 if speed_duration >= 4 else 2
                per_burst_duration = max(1.5, float(speed_duration) / float(num_bursts)) if speed_duration > 0 else float(timeout)

                burst_speeds: List[float] = []
                total_downloaded = 0
                total_duration = 0.0
                burst_url = speed_url_template.format(bytes=target_bytes)

                start_all_bursts = time.perf_counter()
                burst_deadline = start_all_bursts + speed_duration if speed_duration > 0 else start_all_bursts + timeout

                for burst_idx in range(num_bursts):
                    if time.perf_counter() >= burst_deadline - 0.2 and burst_speeds:
                        break
                    try:
                        req_start = time.perf_counter()
                        with requests.get(
                            burst_url,
                            proxies=proxies,
                            timeout=timeout,
                            stream=True,
                            headers={"User-Agent": APP_HEADER},
                        ) as r:
                            if out.ttfb_ms is None:
                                out.ttfb_ms = round((time.perf_counter() - req_start) * 1000.0, 1)

                            if not (200 <= r.status_code < 400):
                                if not out.speed_error:
                                    out.speed_error = f"HTTP {r.status_code}"
                                continue

                            burst_downloaded = 0
                            transfer_start = time.perf_counter()
                            run_deadline = transfer_start + per_burst_duration

                            for chunk in r.iter_content(chunk_size=32 * 1024):
                                if not chunk:
                                    break
                                burst_downloaded += len(chunk)
                                if time.perf_counter() >= run_deadline or time.perf_counter() >= burst_deadline:
                                    break

                            transfer_elapsed = time.perf_counter() - transfer_start
                            if transfer_elapsed > 0.04 and burst_downloaded > 0:
                                b_mbps = (burst_downloaded * 8) / (transfer_elapsed * 1_000_000)
                                burst_speeds.append(b_mbps)
                                total_downloaded += burst_downloaded
                                total_duration += transfer_elapsed
                    except Exception as b_exc:
                        logger.debug("Download burst %d failed for %s: %s", burst_idx + 1, out.endpoint, b_exc)

                if burst_speeds:
                    out.speed_mbps = round(float(statistics.median(burst_speeds)), 2)
                    out.download_bytes = total_downloaded
                    out.download_duration = round(total_duration, 3)
                    out.speed_error = ""
                elif not out.speed_error:
                    out.speed_error = "Insufficient data received"

            # 2. Upload Speed Test (Isolated Handshake & Zero-RAM Stream)
            if test_upload and upload_bytes > 0:
                payload = StreamUploadPayload(upload_bytes)
                try:
                    up_r = requests.post(
                        upload_url,
                        data=payload,
                        proxies=proxies,
                        timeout=max(timeout, speed_duration + 5),
                        headers={"User-Agent": APP_HEADER, "Content-Type": "application/octet-stream"},
                    )
                    if payload.transfer_start is not None and payload.transfer_end is not None:
                        up_elapsed = payload.transfer_end - payload.transfer_start
                    else:
                        up_elapsed = 0.0

                    if 200 <= up_r.status_code < 400 and up_elapsed > 0.02 and payload.bytes_sent > 0:
                        up_mbps = (payload.bytes_sent * 8) / (up_elapsed * 1_000_000)
                        out.upload_mbps = round(up_mbps, 2)
                        out.upload_bytes = payload.bytes_sent
                        out.upload_duration = round(up_elapsed, 3)
                    else:
                        out.upload_error = f"HTTP {up_r.status_code}"
                except Exception as exc:
                    logger.debug("Upload test failed for %s: %s", out.endpoint, exc)
                    out.upload_error = str(exc).split("\n", 1)[0][:100]

    except Exception as exc:
        logger.debug("Speed test failed for %s: %s", out.endpoint, exc)
        out.speed_error = str(exc).split("\n", 1)[0][:100]

    return out


def run_speed_tests(
    v: VlessConfig,
    targets: List[ScanResult],
    xray: Path,
    workers: int = 5,
    timeout: int = 15,
    speed_bytes: int = DEFAULT_SPEED_BYTES,
    speed_duration: int = 5,
    speed_url_template: str = DEFAULT_SPEED_URL,
    loglevel: str = "warning",
    test_upload: bool = True,
    upload_bytes: int = DEFAULT_UPLOAD_BYTES,
    upload_url: str = DEFAULT_UPLOAD_URL,
    on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
) -> List[ScanResult]:
    """Benchmark download and upload speed concurrently across targets."""
    def _test(r: ScanResult) -> ScanResult:
        return speed_test_ip(
            v,
            r,
            xray,
            timeout,
            speed_bytes,
            speed_duration,
            speed_url_template,
            loglevel,
            test_upload,
            upload_bytes,
            upload_url,
        )

    results = _run_concurrent_tasks(targets, _test, workers, "speed test", on_result=on_result)
    return sorted(results, key=speed_sort_key)


def calc_percentile(sorted_data: List[float], p: float) -> float:
    """Calculate p-th percentile (0.0 to 100.0) from a sorted list of floats."""
    if not sorted_data:
        return 0.0
    if len(sorted_data) == 1:
        return sorted_data[0]
    rank = (p / 100.0) * (len(sorted_data) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(sorted_data) - 1)
    weight = rank - lower
    return sorted_data[lower] * (1.0 - weight) + sorted_data[upper] * weight


def calc_rfc_jitter(latencies: List[float]) -> float:
    """Calculate RFC 3393 / RFC 3550 statistical network jitter: mean consecutive difference."""
    if len(latencies) < 2:
        return 0.0
    diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    return sum(diffs) / len(diffs)


def summarize_latency(results: List[ScanResult]) -> ScanResult:
    """Calculate statistical latency metrics: median, RFC 3393 jitter, p90, and stddev."""
    if not results:
        return ScanResult(ip="", port=0, ok=False, error="No samples")

    base = replace(results[0])
    valid_latencies = sorted(r.latency_ms for r in results if r.ok and r.latency_ms is not None)
    passed = len(valid_latencies)
    total = len(results)

    base.recheck_passed = passed
    base.recheck_total = total
    base.packet_loss = ((total - passed) / total) * 100.0 if total > 0 else 100.0

    if valid_latencies:
        base.latency_ms = statistics.median(valid_latencies)
        base.jitter_ms = calc_rfc_jitter([r.latency_ms for r in results if r.ok and r.latency_ms is not None])
        p90 = calc_percentile(valid_latencies, 90.0)
        std_dev = statistics.stdev(valid_latencies) if len(valid_latencies) > 1 else 0.0
        base.latency_stats = f"median={base.latency_ms:.1f}ms, p90={p90:.1f}ms, stddev={std_dev:.1f}ms"
        base.error = ""
        base.ok = True
    else:
        base.ok = False
        base.latency_ms = None
        base.jitter_ms = None
        base.error = "100% packet loss"

    return base


def retest_ip_latency(
    v: VlessConfig,
    base_result: ScanResult,
    xray: Path,
    timeout: int = 3,
    sample_count: int = 8,
    url: str = DEFAULT_URL,
    loglevel: str = "warning",
) -> ScanResult:
    """Retest endpoint latency across multiple spaced samples using a single shared XrayProcess."""
    ip = base_result.ip
    port = base_result.port
    samples: List[ScanResult] = []

    if requests is None:
        out = replace(base_result)
        out.ok = False
        out.error = "requests[socks] not installed"
        return out

    try:
        with XrayProcess(xray, v, ip, port, loglevel=loglevel, ready_timeout=min(3.0, float(timeout))) as xp:
            for i in range(sample_count):
                if i > 0:
                    time.sleep(random.uniform(0.2, 0.5))
                start = time.perf_counter()
                try:
                    r = requests.get(url, proxies=xp.proxies, timeout=timeout, headers={"User-Agent": APP_HEADER})
                    lat = (time.perf_counter() - start) * 1000
                    if 200 <= r.status_code < 400:
                        samples.append(ScanResult(ip=ip, port=port, ok=True, latency_ms=lat, status_code=r.status_code))
                    else:
                        samples.append(ScanResult(ip=ip, port=port, ok=False, error=f"HTTP {r.status_code}"))
                except Exception as exc:
                    logger.debug("Sample %d failed for %s:%d: %s", i + 1, ip, port, exc)
                    samples.append(ScanResult(ip=ip, port=port, ok=False, error=str(exc)[:60]))
    except Exception as exc:
        logger.debug("Failed to spawn Xray for retest of %s:%d: %s", ip, port, exc)
        for _ in range(sample_count):
            samples.append(ScanResult(ip=ip, port=port, ok=False, error="Xray process error"))

    summary = summarize_latency(samples)
    summary.colo = base_result.colo
    return summary


def run_latency_recheck(
    v: VlessConfig,
    ok_results: List[ScanResult],
    xray: Path,
    workers: int = 5,
    timeout: int = 3,
    sample_count: int = 8,
    url: str = DEFAULT_URL,
    loglevel: str = "warning",
    on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
) -> List[ScanResult]:
    """Execute latency stability and jitter recheck across candidate endpoints."""
    targets = sorted(ok_results, key=lambda r: r.latency_ms if r.latency_ms is not None else 10**9)
    if not targets:
        return []

    def _test(t: ScanResult) -> ScanResult:
        return retest_ip_latency(v, t, xray, timeout, sample_count, url, loglevel)

    results = _run_concurrent_tasks(targets, _test, workers, "latency re-check", on_result=on_result)
    return sorted(results, key=recheck_sort_key)


DEFAULT_STREAM_URL = "https://speed.cloudflare.com/__down?bytes=50000000"


def longevity_test_ip(
    v: VlessConfig,
    base_result: ScanResult,
    xray: Path,
    duration: int = DEFAULT_LONGEVITY_DURATION,
    timeout: int = 5,
    stream_url: str = DEFAULT_STREAM_URL,
    loglevel: str = "warning",
    abort_event: Optional[threading.Event] = None,
    **kwargs: Any,
) -> ScanResult:
    """Run continuous stream endurance test evaluating DPI resilience and packet drop over time.

    Methodology:
    - Sustained Data Flow: Unlike micro-pings (generate_204) which bypass deep packet inspection (DPI),
      this test pulls a continuous high-volume binary stream for the specified duration (e.g. 30s).
    - False-Negative Prevention: If a fast connection finishes downloading early, it immediately loops
      to continue streaming so fast endpoints are never penalized.
    - Soft-Stall vs Hard-Drop Detection:
      * Soft-Stall: If DPI throttles the connection to zero throughput without sending a TCP RST packet,
        a socket ReadTimeout occurs after `timeout` seconds of silence.
      * Hard-Drop: If the firewall sends a TCP RST packet or tears down the TLS layer, a ConnectionError
        (ConnectionResetError / ProtocolError) occurs immediately.
      * Loss Percentage: Drop percentage is evaluated as the proportion of unstreamed test duration
        relative to total test duration. Endpoints with loss <= 5% and sustained bytes pass.
    """
    ip = base_result.ip
    port = base_result.port
    out = replace(base_result)

    if requests is None:
        out.sustained = False
        out.longevity_loss = 100.0
        return out

    # Handle legacy url keyword argument if provided
    effective_stream_url = kwargs.get("url") if ("url" in kwargs and stream_url == DEFAULT_STREAM_URL and kwargs.get("url", "").startswith("http")) else stream_url

    total_bytes = 0
    stream_interrupted = False
    fail_time: Optional[float] = None

    try:
        with XrayProcess(xray, v, ip, port, loglevel=loglevel, ready_timeout=min(3.0, float(timeout))) as xp:
            start_time = time.perf_counter()
            end_time = start_time + duration

            while time.perf_counter() < end_time and not stream_interrupted:
                if abort_event is not None and abort_event.is_set():
                    break
                try:
                    with requests.get(
                        effective_stream_url,
                        proxies=xp.proxies,
                        timeout=max(timeout, 5),
                        stream=True,
                        headers={"User-Agent": APP_HEADER},
                    ) as r:
                        if not (200 <= r.status_code < 400):
                            stream_interrupted = True
                            fail_time = time.perf_counter()
                            logger.debug("Longevity HTTP status %d for %s", r.status_code, out.endpoint)
                            break

                        for chunk in r.iter_content(chunk_size=32 * 1024):
                            if abort_event is not None and abort_event.is_set():
                                try:
                                    r.close()
                                except Exception:
                                    pass
                                break
                            if chunk:
                                total_bytes += len(chunk)
                            if time.perf_counter() >= end_time:
                                break
                except (requests.exceptions.ReadTimeout, TimeoutError) as exc:
                    # Soft-stall: DPI throttled stream to zero bytes
                    logger.debug("Longevity soft-stall (ReadTimeout) for %s: %s", out.endpoint, exc)
                    stream_interrupted = True
                    fail_time = time.perf_counter()
                    break
                except (requests.exceptions.ConnectionError, OSError) as exc:
                    # Hard-drop: DPI firewall injected TCP RST or severed TLS connection
                    logger.debug("Longevity hard-drop (ConnectionReset/RST) for %s: %s", out.endpoint, exc)
                    stream_interrupted = True
                    fail_time = time.perf_counter()
                    break
                except Exception as exc:
                    logger.debug("Longevity stream failure for %s: %s", out.endpoint, exc)
                    stream_interrupted = True
                    fail_time = time.perf_counter()
                    break

            if stream_interrupted and fail_time is not None:
                dropped_time = max(0.0, end_time - fail_time)
                loss_pct = (dropped_time / duration) * 100.0
            else:
                loss_pct = 0.0

            out.longevity_loss = round(loss_pct, 1)
            out.sustained = bool(total_bytes > 100_000 and loss_pct <= 5.0)

    except Exception as exc:
        logger.debug("Longevity test failed for %s: %s", out.endpoint, exc)
        out.sustained = False
        out.longevity_loss = 100.0

    return out


def run_longevity_tests(
    v: VlessConfig,
    ok_results: List[ScanResult],
    xray: Path,
    workers: int = 5,
    duration: int = DEFAULT_LONGEVITY_DURATION,
    timeout: int = 5,
    stream_url: str = DEFAULT_STREAM_URL,
    loglevel: str = "warning",
    on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
    abort_event: Optional[threading.Event] = None,
    **kwargs: Any,
) -> List[ScanResult]:
    """Run sustained endurance (Anti-Drop) tests concurrently across endpoints."""
    targets = [r for r in ok_results if r.ok]
    if not targets:
        return []

    target_stream_url = kwargs.get("url") if ("url" in kwargs and stream_url == DEFAULT_STREAM_URL and kwargs.get("url", "").startswith("http")) else stream_url
    ev = abort_event or threading.Event()

    def _test(r: ScanResult) -> ScanResult:
        return longevity_test_ip(
            v, r, xray, duration=duration, timeout=timeout, stream_url=target_stream_url, loglevel=loglevel, abort_event=ev
        )

    try:
        results = _run_concurrent_tasks(targets, _test, workers, "anti-drop test", on_result=on_result, abort_event=ev)
    except ScanInterrupted:
        ev.set()
        raise
    return sorted(results, key=longevity_sort_key)


def run_latency_scan(
    v: VlessConfig,
    target_pairs: List[Tuple[str, int]],
    xray: Path,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: int = DEFAULT_TIMEOUT,
    tries: int = DEFAULT_TRIES,
    url: str = DEFAULT_URL,
    loglevel: str = "warning",
    on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
) -> List[ScanResult]:
    """Execute initial Xray latency scan across candidate endpoints."""
    def _test(pair: Tuple[str, int]) -> ScanResult:
        ip, port = pair
        return test_ip(v, ip, port, xray, timeout, tries, url, loglevel)

    return _run_concurrent_tasks(target_pairs, _test, concurrency, "scan", on_result=on_result)


def run_scan(
    v: VlessConfig,
    targets: List[str],
    ports: List[int],
    xray: Path,
    concurrency: int,
    timeout: int,
    tries: int = 1,
    url: str = DEFAULT_URL,
    loglevel: str = "warning",
    use_tcp_prefilter: bool = True,
    output_dir: Optional[Path] = None,
    on_stage: Optional[Callable[[str, str, str], None]] = None,
    on_message: Optional[Callable[[str, str], None]] = None,
    make_reporter: Optional[Callable[[str, int, str], Any]] = None,
    on_prefilter_progress: Optional[Callable[[int, int, int], None]] = None,
) -> List[ScanResult]:
    """Execute complete initial scan across targets and ports in a headless, decoupled pipeline."""
    target_pairs: List[Tuple[str, int]] = []
    seen_pairs = set()
    for t in targets:
        host, explicit_port = parse_ip_and_port(t)
        if explicit_port is not None:
            if (host, explicit_port) not in seen_pairs:
                seen_pairs.add((host, explicit_port))
                target_pairs.append((host, explicit_port))
        else:
            for p in ports:
                if (host, p) not in seen_pairs:
                    seen_pairs.add((host, p))
                    target_pairs.append((host, p))
    if not target_pairs:
        return []

    if use_tcp_prefilter and len(target_pairs) > 1:
        if on_stage:
            on_stage("Fast TCP Pre-filter", f"Testing TCP connectivity on {len(target_pairs)} candidate endpoints...", "cyan")
        alive = fast_tcp_filter(
            target_pairs,
            timeout=min(1.5, float(timeout)),
            workers=min(30, max(10, concurrency)),
            on_progress=on_prefilter_progress,
        )
        if alive:
            if on_message:
                on_message(f"TCP pre-filter passed: {len(alive)} / {len(target_pairs)} endpoints", "green")
            target_pairs = alive
            try:
                alive_file, ips_file = save_tcp_alive_endpoints(alive, output_dir=output_dir)
                if on_message:
                    on_message(f"Saved {len(alive)} TCP-alive endpoints to: {alive_file.name} & {ips_file.name}", "cyan")
            except Exception as e:
                logger.debug("Failed to save TCP alive endpoints: %s", e)
                if on_message:
                    on_message(f"Warning: Could not save TCP-alive endpoints: {e}", "yellow")
        else:
            if on_message:
                on_message("No endpoints passed TCP pre-filter. Testing all endpoints directly with Xray...", "yellow")

    if on_stage:
        on_stage("Xray Latency Scan", f"Testing {len(target_pairs)} endpoint(s) with Xray...", "cyan")

    if make_reporter:
        with make_reporter("Scanning", len(target_pairs), mode="latency") as reporter:
            return run_latency_scan(
                v,
                target_pairs,
                xray,
                concurrency=concurrency,
                timeout=timeout,
                tries=tries,
                url=url,
                loglevel=loglevel,
                on_result=reporter,
            )
    else:
        return run_latency_scan(
            v,
            target_pairs,
            xray,
            concurrency=concurrency,
            timeout=timeout,
            tries=tries,
            url=url,
            loglevel=loglevel,
        )


def resolve_endpoint_colo(
    v: VlessConfig,
    ip: str,
    port: int,
    xray: Path,
    timeout: int = 3,
) -> Optional[str]:
    """Query https://cloudflare.com/cdn-cgi/trace via Xray proxy to detect Cloudflare edge PoP (Colo)."""
    if requests is None:
        return None
    try:
        with XrayProcess(xray, v, ip, port, loglevel="warning", ready_timeout=min(3.0, float(timeout))) as xp:
            r = requests.get(CF_TRACE_URL, proxies=xp.proxies, timeout=timeout, headers={"User-Agent": APP_HEADER})
            if 200 <= r.status_code < 400 and r.text:
                return parse_cf_colo(r.text)
    except Exception as exc:
        logger.debug("resolve_endpoint_colo failed for %s:%d: %s", ip, port, exc)
    return None


def enrich_results_with_colo(
    v: VlessConfig,
    results: List[ScanResult],
    xray: Path,
    workers: int = 10,
    timeout: int = 3,
) -> None:
    """Concurrently resolve Cloudflare edge colo airport code using BatchXrayProcess."""
    enrich_results_with_geoip(results, workers=workers, timeout=timeout)
    targets = [r for r in results if r.ok and not r.colo]
    if not targets or requests is None:
        return

    # Process in batches of 15 endpoints per Xray process to prevent process spawning overhead
    batch_size = 15
    for i in range(0, len(targets), batch_size):
        chunk = targets[i : i + batch_size]
        endpoint_tuples = [(r.ip, r.port) for r in chunk]
        try:
            with BatchXrayProcess(xray, v, endpoint_tuples, ready_timeout=float(timeout) + 1.0) as bxp:
                def _fetch(r: ScanResult) -> None:
                    proxies = bxp.get_proxies_for_endpoint(r.ip, r.port)
                    if not proxies:
                        return
                    try:
                        resp = requests.get(CF_TRACE_URL, proxies=proxies, timeout=timeout, headers={"User-Agent": APP_HEADER})
                        if 200 <= resp.status_code < 400 and resp.text:
                            r.colo = parse_cf_colo(resp.text)
                    except Exception as exc:
                        logger.debug("Failed colo request for %s: %s", r.endpoint, exc)

                with ThreadPoolExecutor(max_workers=min(workers, len(chunk))) as ex:
                    list(ex.map(_fetch, chunk))
        except Exception as exc:
            logger.debug("BatchXrayProcess failed for chunk, falling back to individual resolution: %s", exc)
            for r in chunk:
                r.colo = resolve_endpoint_colo(v, r.ip, r.port, xray, timeout=timeout)


def run_stability_stage(
    v: VlessConfig,
    candidates: List[ScanResult],
    xray: Path,
    workers: int,
    timeout: int,
    samples: int,
    test_url: str,
    loglevel: str = "warning",
    on_stage: Optional[Callable[[str, str, str], None]] = None,
    make_reporter: Optional[Callable[[str, int, str], Any]] = None,
) -> List[ScanResult]:
    """Execute latency recheck and stability testing with optional UI reporter."""
    if on_stage:
        on_stage("Testing Stability & Jitter", f"Testing {len(candidates)} endpoints ({samples} pings each)...", "magenta")
    if make_reporter:
        with make_reporter("Stability & Jitter", len(candidates), mode="recheck") as cb:
            return run_latency_recheck(
                v, candidates, xray, workers, timeout, samples, test_url, loglevel, on_result=cb
            )
    return run_latency_recheck(v, candidates, xray, workers, timeout, samples, test_url, loglevel)


def run_longevity_stage(
    v: VlessConfig,
    candidates: List[ScanResult],
    xray: Path,
    workers: int,
    duration: int,
    timeout: int,
    loglevel: str = "warning",
    on_stage: Optional[Callable[[str, str, str], None]] = None,
    make_reporter: Optional[Callable[[str, int, str], Any]] = None,
    abort_event: Optional[threading.Event] = None,
) -> List[ScanResult]:
    """Execute Anti-Drop endurance testing with optional UI reporter."""
    if on_stage:
        on_stage("Testing Anti-Drop (DPI Endurance)", f"Testing sustained connection on {len(candidates)} endpoints ({duration}s continuous)...", "green")
    if make_reporter:
        with make_reporter("Anti-Drop Endurance", len(candidates), mode="longevity") as cb:
            return run_longevity_tests(
                v, candidates, xray, workers=workers, duration=duration, timeout=timeout,
                loglevel=loglevel, on_result=cb, abort_event=abort_event
            )
    return run_longevity_tests(
        v, candidates, xray, workers=workers, duration=duration, timeout=timeout,
        loglevel=loglevel, abort_event=abort_event
    )


def run_speed_stage(
    v: VlessConfig,
    candidates: List[ScanResult],
    xray: Path,
    workers: int,
    duration: int,
    timeout: int,
    download_mb: int,
    upload_mb: int = 0,
    speed_url: str = DEFAULT_SPEED_URL,
    upload_url: str = DEFAULT_UPLOAD_URL,
    loglevel: str = "warning",
    on_stage: Optional[Callable[[str, str, str], None]] = None,
    make_reporter: Optional[Callable[[str, int, str], Any]] = None,
) -> List[ScanResult]:
    """Execute bandwidth download and upload benchmarking with optional UI reporter."""
    up_text = f", {upload_mb}MB up" if upload_mb > 0 else ""
    if on_stage:
        on_stage("Testing Download & Upload Speed", f"Testing speed on {len(candidates)} endpoints ({download_mb}MB down{up_text})...", "magenta")
    test_upload = upload_mb > 0
    if make_reporter:
        with make_reporter("Speed Testing", len(candidates), mode="speed") as cb:
            return run_speed_tests(
                v, candidates, xray, workers, max(timeout, duration + 10),
                mb_to_bytes(download_mb), duration, speed_url, loglevel,
                test_upload=test_upload, upload_bytes=mb_to_bytes(upload_mb),
                upload_url=upload_url, on_result=cb,
            )
    return run_speed_tests(
        v, candidates, xray, workers, max(timeout, duration + 10),
        mb_to_bytes(download_mb), duration, speed_url, loglevel,
        test_upload=test_upload, upload_bytes=mb_to_bytes(upload_mb),
        upload_url=upload_url,
    )


def execute_configured_post_scan_tests(
    settings: AppSettings,
    v: VlessConfig,
    working_results: List[ScanResult],
    xray: Path,
    output_dir: Path,
    on_stage: Optional[Callable[[str, str, str], None]] = None,
    on_message: Optional[Callable[[str, str], None]] = None,
    make_reporter: Optional[Callable[[str, int, str], Any]] = None,
) -> Tuple[List[ScanResult], Path, Path, str]:
    """Execute post-scan stability and/or speed testing automatically according to AppSettings."""
    if not working_results:
        txt, csvp = save_results(working_results, output_dir, "clean_ips", vless_config=v)
        return working_results, txt, csvp, "clean_ips"

    if settings.post_scan_mode == "none":
        enrich_results_with_colo(v, working_results, xray, workers=min(settings.workers, 20), timeout=settings.timeout)
        txt, csvp = save_results(working_results, output_dir, "clean_ips", vless_config=v)
        return working_results, txt, csvp, "clean_ips"

    sorted_working = sorted(working_results, key=latency_sort_key)
    candidates = sorted_working if (settings.top_targets <= 0 or settings.top_targets >= len(sorted_working)) else sorted_working[: settings.top_targets]
    abort_event = threading.Event()

    # Mode: Full (Stability + Anti-Drop + Speed)
    if settings.post_scan_mode == "full":
        stability_candidates = sorted_working if (settings.top_targets <= 0 or len(sorted_working) <= max(settings.top_targets, 50)) else sorted_working[: max(settings.top_targets, 50)]
        try:
            rechecked = run_stability_stage(
                v, stability_candidates, xray, settings.speed_workers, settings.timeout,
                settings.ping_samples, settings.test_url, on_stage=on_stage, make_reporter=make_reporter,
            )
        except ScanInterrupted as interrupted:
            rechecked = interrupted.results
            txt, csvp = save_results(rechecked, output_dir, "clean_ips_full_interrupted", vless_config=v)
            return rechecked, txt, csvp, "clean_ips_full_interrupted"

        survivors = [r for r in rechecked if r.ok and r.packet_loss < 100.0]
        if not survivors:
            if on_message:
                on_message("No endpoints survived stability test.", "yellow")
            txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked", vless_config=v)
            return rechecked, txt, csvp, "clean_ips_rechecked"

        if settings.longevity_test:
            try:
                survivors = run_longevity_stage(
                    v, survivors, xray, min(settings.speed_workers, 5), settings.longevity_duration,
                    settings.timeout, on_stage=on_stage, make_reporter=make_reporter, abort_event=abort_event,
                )
            except ScanInterrupted as interrupted:
                survivors = interrupted.results
                txt, csvp = save_results(survivors, output_dir, "clean_ips_full_interrupted", vless_config=v)
                return survivors, txt, csvp, "clean_ips_full_interrupted"

        speed_candidates = sorted(survivors, key=recheck_sort_key)[: settings.top_targets] if (settings.top_targets > 0 and len(survivors) > settings.top_targets) else survivors

        try:
            tested = run_speed_stage(
                v, speed_candidates, xray, settings.speed_workers, settings.speed_duration,
                settings.timeout, settings.download_mb, settings.upload_mb,
                on_stage=on_stage, make_reporter=make_reporter,
            )
        except ScanInterrupted as interrupted:
            tested = interrupted.results
            txt, csvp = save_results(tested, output_dir, "clean_ips_full_interrupted", include_speed_errors=True, vless_config=v)
            return tested, txt, csvp, "clean_ips_full_interrupted"

        enrich_results_with_colo(v, tested, xray, workers=settings.speed_workers, timeout=settings.timeout)
        tested = sorted(tested, key=full_sort_key)
        txt, csvp = save_results(tested, output_dir, "clean_ips_full_tested", include_speed_errors=True, vless_config=v)
        return tested, txt, csvp, "clean_ips_full_tested"

    # Mode: Stability only
    elif settings.post_scan_mode == "stability":
        try:
            rechecked = run_stability_stage(
                v, candidates, xray, settings.speed_workers, settings.timeout,
                settings.ping_samples, settings.test_url, on_stage=on_stage, make_reporter=make_reporter,
            )
        except ScanInterrupted as interrupted:
            rechecked = interrupted.results
            txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked_interrupted", vless_config=v)
            return rechecked, txt, csvp, "clean_ips_rechecked_interrupted"

        if settings.longevity_test:
            survivors = [r for r in rechecked if r.ok and r.packet_loss < 100.0]
            if survivors:
                try:
                    rechecked = run_longevity_stage(
                        v, survivors, xray, min(settings.speed_workers, 5), settings.longevity_duration,
                        settings.timeout, on_stage=on_stage, make_reporter=make_reporter, abort_event=abort_event,
                    )
                except ScanInterrupted as interrupted:
                    rechecked = interrupted.results
                    txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked_interrupted", vless_config=v)
                    return rechecked, txt, csvp, "clean_ips_rechecked_interrupted"

        enrich_results_with_colo(v, rechecked, xray, workers=settings.speed_workers, timeout=settings.timeout)
        txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked", vless_config=v)
        return rechecked, txt, csvp, "clean_ips_rechecked"

    # Mode: Longevity only
    elif settings.post_scan_mode == "longevity":
        try:
            tested = run_longevity_stage(
                v, candidates, xray, min(settings.speed_workers, 5), settings.longevity_duration,
                settings.timeout, on_stage=on_stage, make_reporter=make_reporter, abort_event=abort_event,
            )
            enrich_results_with_colo(v, tested, xray, workers=settings.speed_workers, timeout=settings.timeout)
            txt, csvp = save_results(tested, output_dir, "clean_ips_longevity", vless_config=v)
            return tested, txt, csvp, "clean_ips_longevity"
        except ScanInterrupted as interrupted:
            tested = interrupted.results
            txt, csvp = save_results(tested, output_dir, "clean_ips_longevity_interrupted", vless_config=v)
            return tested, txt, csvp, "clean_ips_longevity_interrupted"

    # Mode: Speed only
    elif settings.post_scan_mode == "speed":
        try:
            tested = run_speed_stage(
                v, candidates, xray, settings.speed_workers, settings.speed_duration,
                settings.timeout, settings.download_mb, settings.upload_mb,
                on_stage=on_stage, make_reporter=make_reporter,
            )
            enrich_results_with_colo(v, tested, xray, workers=settings.speed_workers, timeout=settings.timeout)
            txt, csvp = save_results(tested, output_dir, "clean_ips_speed_tested", include_speed_errors=True, vless_config=v)
            return tested, txt, csvp, "clean_ips_speed_tested"
        except ScanInterrupted as interrupted:
            tested = interrupted.results
            txt, csvp = save_results(tested, output_dir, "clean_ips_speed_tested_interrupted", include_speed_errors=True, vless_config=v)
            return tested, txt, csvp, "clean_ips_speed_tested_interrupted"

    # Fallback / None
    enrich_results_with_colo(v, working_results, xray, workers=min(settings.workers, 20), timeout=settings.timeout)
    txt, csvp = save_results(working_results, output_dir, "clean_ips", vless_config=v)
    return working_results, txt, csvp, "clean_ips"


class ScannerEngine:
    """Headless scanning and diagnostic engine for Cloudflare clean IPs."""

    def __init__(self, xray_path: Optional[Path] = None):
        from scanner.xray import find_xray
        self.xray_path = xray_path or find_xray()

    def filter_tcp(self, target_pairs: List[Tuple[str, int]], timeout: float = 1.0, workers: int = 80) -> List[Tuple[str, int]]:
        return fast_tcp_filter(target_pairs, timeout=timeout, workers=workers)

    def scan(
        self,
        vless: VlessConfig,
        targets: List[str],
        ports: List[int],
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: int = DEFAULT_TIMEOUT,
        url: str = DEFAULT_URL,
        use_tcp_prefilter: bool = True,
        output_dir: Optional[Path] = None,
        on_stage: Optional[Callable[[str, str, str], None]] = None,
        on_message: Optional[Callable[[str, str], None]] = None,
        make_reporter: Optional[Callable[[str, int, str], Any]] = None,
    ) -> List[ScanResult]:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        return run_scan(
            v=vless,
            targets=targets,
            ports=ports,
            xray=self.xray_path,
            concurrency=concurrency,
            timeout=timeout,
            url=url,
            use_tcp_prefilter=use_tcp_prefilter,
            output_dir=output_dir,
            on_stage=on_stage,
            on_message=on_message,
            make_reporter=make_reporter,
        )

    def recheck(
        self,
        vless: VlessConfig,
        results: List[ScanResult],
        sample_count: int = 8,
        workers: int = 5,
        timeout: int = 3,
        url: str = DEFAULT_URL,
        on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
    ) -> List[ScanResult]:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        return run_latency_recheck(
            v=vless,
            ok_results=results,
            xray=self.xray_path,
            workers=workers,
            timeout=timeout,
            sample_count=sample_count,
            url=url,
            on_result=on_result,
        )

    def test_longevity(
        self,
        vless: VlessConfig,
        results: List[ScanResult],
        duration: int = DEFAULT_LONGEVITY_DURATION,
        workers: int = 5,
        timeout: int = 5,
        stream_url: str = DEFAULT_STREAM_URL,
        on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
    ) -> List[ScanResult]:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        return run_longevity_tests(
            v=vless,
            ok_results=results,
            xray=self.xray_path,
            workers=workers,
            duration=duration,
            timeout=timeout,
            stream_url=stream_url,
            on_result=on_result,
        )

    def test_speed(
        self,
        vless: VlessConfig,
        results: List[ScanResult],
        download_mb: int = 5,
        upload_mb: int = 1,
        duration: int = 5,
        workers: int = 5,
        on_result: Optional[Callable[[ScanResult, int, int], None]] = None,
    ) -> List[ScanResult]:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        return run_speed_tests(
            v=vless,
            targets=results,
            xray=self.xray_path,
            workers=workers,
            timeout=duration + 10,
            speed_bytes=mb_to_bytes(download_mb),
            speed_duration=duration,
            speed_url_template=DEFAULT_SPEED_URL,
            test_upload=(upload_mb > 0),
            upload_bytes=mb_to_bytes(upload_mb),
            on_result=on_result,
        )

    def resolve_colo(self, vless: VlessConfig, ip: str, port: int, timeout: int = 3) -> Optional[str]:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        return resolve_endpoint_colo(vless, ip, port, self.xray_path, timeout=timeout)

    def enrich_colo(self, vless: VlessConfig, results: List[ScanResult], workers: int = 10, timeout: int = 3) -> None:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        enrich_results_with_colo(vless, results, self.xray_path, workers=workers, timeout=timeout)
