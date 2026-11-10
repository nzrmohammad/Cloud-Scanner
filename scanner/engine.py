from __future__ import annotations

import asyncio
import os
import random
import socket
import statistics
import struct
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
    format_host_port,
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
from scanner.xray import (
    BatchXrayProcess,
    XrayProcess,
    XrayStartupError,
    terminate_active_xray_processes,
)

logger = get_logger("engine")

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]


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
    prior_results: Optional[List[R]] = None,
) -> List[R]:
    """Execute task_fn concurrently across items with KeyboardInterrupt cancellation."""
    if not items:
        return []

    ev = abort_event if abort_event is not None else threading.Event()
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
        ev.set()
        logger.warning("KeyboardInterrupt received in %s, canceling %d futures", stage_name, len(futures))
        for fut in futures:
            fut.cancel()
        terminate_active_xray_processes()
        ex.shutdown(wait=False, cancel_futures=True)
        partial = (list(prior_results) if prior_results else []) + results
        raise ScanInterrupted(partial, stage_name) from exc
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
    """Filter candidate endpoints using high-concurrency non-blocking asyncio TCP handshakes."""
    total = len(target_pairs)
    if total == 0:
        return []

    # Cap concurrent TCP handshakes on Windows to avoid WSAENOBUFS / ephemeral port exhaustion
    if os.name == "nt":
        max_w = min(max(workers, 20), total, 30)
    else:
        max_w = min(max(workers * 2, 60), total, 100)
    alive: List[Tuple[str, int]] = []
    linger_bytes = struct.pack("ii", 1, 0)

    async def _probe_all() -> List[Tuple[str, int]]:
        loop = asyncio.get_running_loop()
        sem = asyncio.Semaphore(max_w)
        done = 0

        async def _probe_one(pair: Tuple[str, int]) -> None:
            nonlocal done
            ip, port = pair
            ok = False
            async with sem:
                sock: Optional[socket.socket] = None
                try:
                    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=timeout)
                    # Reset cleanly on close to avoid TIME_WAIT socket exhaustion
                    try:
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger_bytes)
                    except OSError as exc:
                        logger.debug("SO_LINGER setup skipped for %s:%d: %s", ip, port, exc)
                    ok = True
                except (asyncio.TimeoutError, OSError):
                    ok = False
                finally:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError as exc:
                            logger.debug("Closing TCP prefilter socket failed for %s:%d: %s", ip, port, exc)

            if ok:
                alive.append(pair)
            done += 1
            if on_progress:
                try:
                    on_progress(done, total, len(alive))
                except Exception as exc:
                    logger.debug("Prefilter on_progress error: %s", exc)

        tasks = [asyncio.create_task(_probe_one(pair)) for pair in target_pairs]
        try:
            await asyncio.gather(*tasks)
        except BaseException:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        return alive

    try:
        return asyncio.run(_probe_all())
    except KeyboardInterrupt as exc:
        raise ScanInterrupted([], "tcp_prefilter") from exc


def save_tcp_alive_endpoints(
    alive_endpoints: List[Tuple[str, int]],
    output_dir: Optional[Path] = None,
) -> Tuple[Path, Path]:
    """Save TCP-prefiltered alive endpoints (IP:port) and unique IPs to files."""
    if output_dir is None:
        output_dir = app_dir() / "results"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    tcp_alive_file = output_dir / "tcp_alive_with_port.txt"
    tcp_ips_file = output_dir / "tcp_alive_ips.txt"

    endpoint_lines = [
        "# Cloud Scanner - Fast TCP Pre-filter Alive Endpoints (IP:port)",
        f"# Total alive: {len(alive_endpoints)} | Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    endpoint_lines.extend(format_host_port(ip, port) for ip, port in alive_endpoints)
    tcp_alive_file.write_text("\n".join(endpoint_lines) + "\n", encoding="utf-8")

    unique_ips = list(dict.fromkeys(ip for ip, _ in alive_endpoints))
    ip_lines = [
        "# Cloud Scanner - Fast TCP Pre-filter Unique Alive IPs",
        f"# Total unique IPs: {len(unique_ips)} | Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    ip_lines.extend(unique_ips)
    tcp_ips_file.write_text("\n".join(ip_lines) + "\n", encoding="utf-8")

    return tcp_alive_file, tcp_ips_file


def _probe_via_proxies(
    ip: str,
    port: int,
    proxies: dict[str, str],
    timeout: int,
    url: str,
) -> Tuple[Optional[ScanResult], str]:
    """Execute one HTTP latency probe over an established SOCKS proxy."""
    if requests is None:
        return ScanResult(ip=ip, port=port, ok=False, error="Python package requests[socks] is not installed"), ""
    start = time.perf_counter()
    r = requests.get(url, proxies=proxies, timeout=timeout, headers={"User-Agent": APP_HEADER})
    latency = (time.perf_counter() - start) * 1000
    if 200 <= r.status_code < 400:
        colo = parse_cf_colo(r.text[:500]) if (r.text and "colo=" in r.text[:500]) else None
        return ScanResult(ip=ip, port=port, ok=True, latency_ms=latency, status_code=r.status_code, colo=colo), ""
    return None, f"HTTP {r.status_code}"


def test_ip(
    v: VlessConfig,
    ip: str,
    port: int,
    xray: Path,
    timeout: int,
    tries: int,
    url: str,
    loglevel: str = "warning",
    abort_event: Optional[threading.Event] = None,
) -> ScanResult:
    """Test a single IP and port through Xray's local SOCKS proxy."""
    if requests is None:
        return ScanResult(ip=ip, port=port, ok=False, error="Python package requests[socks] is not installed")

    last_error = ""
    for _ in range(max(1, tries)):
        if abort_event is not None and abort_event.is_set():
            return ScanResult(ip=ip, port=port, ok=False, error="Aborted")
        try:
            with XrayProcess(xray, v, ip, port, loglevel=loglevel, ready_timeout=min(3.0, float(timeout))) as xp:
                res, err = _probe_via_proxies(ip, port, xp.proxies, timeout, url)
                if res is not None:
                    return res
                last_error = err
        except XrayStartupError as exc:
            if not exc.transient:
                logger.warning("Xray startup failed for %s:%d: %s", ip, port, exc)
                return ScanResult(ip=ip, port=port, ok=False, error=str(exc).split("\n", 1)[0][:160])
            logger.debug("Transient Xray startup error for %s:%d: %s", ip, port, exc)
            last_error = str(exc).split("\n", 1)[0][:160]
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
        self.bytes_sent = 0
        self.transfer_start = None
        self.transfer_end = None
        while self.bytes_sent < self.size:
            if self.transfer_start is None:
                self.transfer_start = time.perf_counter()
            to_send = min(len(self._buffer), self.size - self.bytes_sent)
            self.bytes_sent += to_send
            yield self._buffer[:to_send]
        self.transfer_end = time.perf_counter()

    def __len__(self) -> int:
        return self.size


def _run_upload_probe(
    session: Any,
    upload_url: str,
    size_bytes: int,
    timeout_s: float,
    rtt_sec: float,
) -> Tuple[Optional[float], int, Optional[float], str]:
    """Execute one streaming upload probe and return (mbps, bytes_sent, duration_s, error)."""
    payload = StreamUploadPayload(size_bytes)
    up_start = time.perf_counter()
    up_r = session.post(
        upload_url,
        data=payload,
        timeout=timeout_s,
        headers={"User-Agent": APP_HEADER, "Content-Type": "application/octet-stream"},
    )
    up_elapsed = time.perf_counter() - up_start
    if 200 <= up_r.status_code < 400 and up_elapsed > 0.02 and size_bytes > 0:
        effective = up_elapsed - rtt_sec if (rtt_sec > 0 and up_elapsed > rtt_sec + 0.05) else up_elapsed
        effective = max(0.04, effective)
        mbps = (size_bytes * 8) / (effective * 1_000_000)
        return round(mbps, 2), size_bytes, round(effective, 3), ""
    return None, 0, None, f"HTTP {up_r.status_code}"


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
    abort_event: Optional[threading.Event] = None,
) -> ScanResult:
    """Run real download and upload speed tests through Xray for one working endpoint."""
    out = replace(base_result)

    if requests is None:
        out.speed_error = "Python package requests[socks] is not installed"
        return out

    if abort_event is not None and abort_event.is_set():
        out.speed_error = "Aborted"
        return out

    ip, port = base_result.ip, base_result.port
    try:
        with XrayProcess(xray, v, ip, port, loglevel=loglevel, ready_timeout=min(3.0, float(timeout))) as xp:
            preliminary_mbps: Optional[float] = None

            with requests.Session() as session:
                session.proxies = xp.proxies

                # 1. Download Speed Test with Warmup, TTFB isolation, Adaptive Sizing & Median Filtering
                if speed_bytes > 0:
                    warmup_size = min(speed_bytes, mb_to_bytes(1) // 4)
                    warmup_url = speed_url_template.format(bytes=warmup_size)

                    try:
                        w_req_start = time.perf_counter()
                        with session.get(
                            warmup_url,
                            timeout=min(4.0, float(timeout)),
                            stream=True,
                            headers={"User-Agent": APP_HEADER},
                        ) as w:
                            if 200 <= w.status_code < 400:
                                ttfb = (time.perf_counter() - w_req_start) * 1000.0
                                out.ttfb_ms = round(ttfb, 1)

                                w_downloaded = 0
                                w_transfer_start = time.perf_counter()
                                for chunk in w.iter_content(chunk_size=64 * 1024):
                                    if abort_event is not None and abort_event.is_set():
                                        break
                                    if not chunk:
                                        break
                                    w_downloaded += len(chunk)
                                w_elapsed = time.perf_counter() - w_transfer_start
                                if w_elapsed > 0.02 and w_downloaded > 0:
                                    preliminary_mbps = (w_downloaded * 8) / (w_elapsed * 1_000_000)
                    except Exception as exc:
                        logger.debug("Warmup error for %s: %s", out.endpoint, exc)

                    target_bytes = speed_bytes
                    if preliminary_mbps is not None:
                        if preliminary_mbps < 20.0:
                            target_bytes = min(speed_bytes, mb_to_bytes(2))
                        elif preliminary_mbps > 100.0:
                            target_bytes = max(speed_bytes, mb_to_bytes(20))

                    num_bursts = 3 if speed_duration >= 4 else 2
                    per_burst_duration = max(1.5, float(speed_duration) / float(num_bursts)) if speed_duration > 0 else float(timeout)
                    per_burst_timeout = min(float(timeout), max(2.5, per_burst_duration + 2.0))

                    burst_speeds: List[float] = []
                    total_downloaded = 0
                    total_duration = 0.0
                    burst_url = speed_url_template.format(bytes=target_bytes)

                    start_all_bursts = time.perf_counter()
                    burst_deadline = start_all_bursts + speed_duration if speed_duration > 0 else start_all_bursts + timeout

                    for burst_idx in range(num_bursts):
                        if abort_event is not None and abort_event.is_set():
                            break
                        if burst_idx > 0 and time.perf_counter() >= burst_deadline - 0.2:
                            break
                        try:
                            req_start = time.perf_counter()
                            with session.get(
                                burst_url,
                                timeout=per_burst_timeout,
                                stream=True,
                                headers={"User-Agent": APP_HEADER},
                            ) as r:
                                if out.ttfb_ms is None and 200 <= r.status_code < 400:
                                    out.ttfb_ms = round((time.perf_counter() - req_start) * 1000.0, 1)

                                if not (200 <= r.status_code < 400):
                                    if not out.speed_error:
                                        out.speed_error = f"HTTP {r.status_code}"
                                    continue

                                burst_downloaded = 0
                                transfer_start = time.perf_counter()
                                run_deadline = transfer_start + per_burst_duration

                                for chunk in r.iter_content(chunk_size=32 * 1024):
                                    if abort_event is not None and abort_event.is_set():
                                        break
                                    if not chunk:
                                        break
                                    burst_downloaded += len(chunk)
                                    now_t = time.perf_counter()
                                    if now_t >= run_deadline or now_t >= burst_deadline:
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

                # 2. Upload Speed Test (Zero-RAM streaming payload & RTT compensation)
                if test_upload and upload_bytes > 0 and not (abort_event is not None and abort_event.is_set()):
                    target_up_bytes = upload_bytes
                    if preliminary_mbps is not None:
                        if preliminary_mbps < 5.0:
                            target_up_bytes = min(upload_bytes, 100_000)
                        elif preliminary_mbps < 25.0:
                            target_up_bytes = min(upload_bytes, 250_000)
                        elif preliminary_mbps < 80.0:
                            target_up_bytes = min(upload_bytes, 500_000)
                    else:
                        target_up_bytes = min(upload_bytes, 250_000)

                    up_timeout = max(float(timeout), float(speed_duration) + 5.0, 15.0)
                    rtt_sec = (out.ttfb_ms if out.ttfb_ms is not None else (base_result.latency_ms or 0.0)) / 1000.0

                    try:
                        mbps, sent, dur, err = _run_upload_probe(session, upload_url, target_up_bytes, up_timeout, rtt_sec)
                        if mbps is not None:
                            out.upload_mbps, out.upload_bytes, out.upload_duration, out.upload_error = mbps, sent, dur, ""
                        else:
                            out.upload_error = err
                    except Exception as exc:
                        if target_up_bytes > 50_000 and "timed out" in str(exc).lower():
                            try:
                                mbps, sent, dur, err = _run_upload_probe(
                                    session, upload_url, 50_000, min(up_timeout, 8.0), rtt_sec
                                )
                                if mbps is not None:
                                    out.upload_mbps, out.upload_bytes, out.upload_duration, out.upload_error = mbps, sent, dur, ""
                                else:
                                    out.upload_error = err
                            except Exception as fb_exc:
                                logger.debug("Upload fallback failed for %s: %s", out.endpoint, fb_exc)
                                out.upload_error = str(exc).split("\n", 1)[0][:100]
                        else:
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
    abort_event: Optional[threading.Event] = None,
) -> List[ScanResult]:
    """Benchmark download and upload speed concurrently across targets."""
    ev = abort_event or threading.Event()

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
            abort_event=ev,
        )

    results = _run_concurrent_tasks(targets, _test, workers, "speed test", on_result=on_result, abort_event=ev)
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
        first_ok_status = next((r.status_code for r in results if r.ok and r.status_code is not None), base.status_code)
        base.status_code = first_ok_status
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
    abort_event: Optional[threading.Event] = None,
) -> ScanResult:
    """Retest endpoint latency across multiple spaced samples using a shared XrayProcess and Session."""
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
            session = requests.Session()
            session.proxies = xp.proxies
            try:
                for i in range(sample_count):
                    if abort_event is not None and abort_event.is_set():
                        break
                    if i > 0:
                        time.sleep(random.uniform(0.2, 0.5))
                    if abort_event is not None and abort_event.is_set():
                        break
                    start = time.perf_counter()
                    try:
                        r = session.get(url, timeout=timeout, headers={"User-Agent": APP_HEADER})
                        lat = (time.perf_counter() - start) * 1000
                        if 200 <= r.status_code < 400:
                            samples.append(ScanResult(ip=ip, port=port, ok=True, latency_ms=lat, status_code=r.status_code))
                        else:
                            samples.append(ScanResult(ip=ip, port=port, ok=False, error=f"HTTP {r.status_code}"))
                    except Exception as exc:
                        logger.debug("Sample %d failed for %s:%d: %s", i + 1, ip, port, exc)
                        samples.append(ScanResult(ip=ip, port=port, ok=False, error=str(exc)[:60]))
                        # Reset pooled connection so the next probe uses a clean socket
                        try:
                            session.close()
                        except Exception as close_exc:
                            logger.debug("Error resetting session for %s:%d: %s", ip, port, close_exc)
                        session = requests.Session()
                        session.proxies = xp.proxies
            finally:
                try:
                    session.close()
                except Exception as close_exc:
                    logger.debug("Error closing session for %s:%d: %s", ip, port, close_exc)
    except Exception as exc:
        logger.debug("Failed to spawn Xray for retest of %s:%d: %s", ip, port, exc)
        for _ in range(sample_count):
            samples.append(ScanResult(ip=ip, port=port, ok=False, error="Xray process error"))

    if not samples:
        out = replace(base_result)
        out.error = "Aborted"
        return out

    summary = summarize_latency(samples)
    out = replace(base_result)
    out.ok = summary.ok
    out.latency_ms = summary.latency_ms
    out.jitter_ms = summary.jitter_ms
    out.packet_loss = summary.packet_loss
    out.recheck_passed = summary.recheck_passed
    out.recheck_total = summary.recheck_total
    out.latency_stats = summary.latency_stats
    out.error = summary.error
    if summary.status_code is not None:
        out.status_code = summary.status_code
    return out


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
    abort_event: Optional[threading.Event] = None,
) -> List[ScanResult]:
    """Execute latency stability and jitter recheck across candidate endpoints."""
    targets = sorted(ok_results, key=lambda r: r.latency_ms if r.latency_ms is not None else 10**9)
    if not targets:
        return []

    ev = abort_event or threading.Event()

    def _test(t: ScanResult) -> ScanResult:
        return retest_ip_latency(v, t, xray, timeout, sample_count, url, loglevel, abort_event=ev)

    results = _run_concurrent_tasks(targets, _test, workers, "latency re-check", on_result=on_result, abort_event=ev)
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
    """Run continuous stream endurance test evaluating DPI resilience and packet drop over time."""
    ip = base_result.ip
    port = base_result.port
    out = replace(base_result)

    if requests is None:
        out.sustained = False
        out.longevity_loss = 100.0
        return out

    raw_url = kwargs.get("url")
    effective_stream_url: str = str(raw_url) if (raw_url and stream_url == DEFAULT_STREAM_URL and str(raw_url).startswith("http")) else str(stream_url)

    total_bytes = 0
    stream_interrupted = False
    aborted = False
    fail_time: Optional[float] = None

    try:
        with XrayProcess(xray, v, ip, port, loglevel=loglevel, ready_timeout=min(3.0, float(timeout))) as xp:
            start_time = time.perf_counter()
            end_time = start_time + duration
            last_data_time = start_time
            req_timeout = min(max(float(timeout), 3.0), max(3.0, float(duration)))

            while time.perf_counter() < end_time and not stream_interrupted:
                if abort_event is not None and abort_event.is_set():
                    aborted = True
                    break
                try:
                    with requests.get(
                        effective_stream_url,
                        proxies=xp.proxies,
                        timeout=req_timeout,
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
                                aborted = True
                                try:
                                    r.close()
                                except Exception as close_exc:
                                    logger.debug("Closing aborted stream failed for %s: %s", out.endpoint, close_exc)
                                break
                            if chunk:
                                total_bytes += len(chunk)
                                last_data_time = time.perf_counter()
                            if time.perf_counter() >= end_time:
                                break
                except (requests.exceptions.ReadTimeout, TimeoutError) as exc:
                    if abort_event is not None and abort_event.is_set():
                        aborted = True
                        break
                    logger.debug("Longevity soft-stall (ReadTimeout) for %s: %s", out.endpoint, exc)
                    stream_interrupted = True
                    # Attribute loss starting from the last received byte rather than after ReadTimeout fired
                    fail_time = min(last_data_time, end_time)
                    break
                except (requests.exceptions.ConnectionError, OSError) as exc:
                    if abort_event is not None and abort_event.is_set():
                        aborted = True
                        break
                    logger.debug("Longevity hard-drop (ConnectionReset/RST) for %s: %s", out.endpoint, exc)
                    stream_interrupted = True
                    fail_time = min(time.perf_counter(), end_time)
                    break
                except Exception as exc:
                    if abort_event is not None and abort_event.is_set():
                        aborted = True
                        break
                    logger.debug("Longevity stream failure for %s: %s", out.endpoint, exc)
                    stream_interrupted = True
                    fail_time = min(time.perf_counter(), end_time)
                    break

            if aborted:
                out.sustained = None
                out.longevity_loss = None
                out.error = "Aborted"
                return out

            if stream_interrupted and fail_time is not None:
                dropped_time = max(0.0, end_time - fail_time)
                loss_pct = min(100.0, (dropped_time / max(1e-6, float(duration))) * 100.0)
            elif total_bytes <= 100_000:
                loss_pct = 100.0
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

    raw_url = kwargs.get("url")
    target_stream_url: str = str(raw_url) if (raw_url and stream_url == DEFAULT_STREAM_URL and str(raw_url).startswith("http")) else str(stream_url)
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
    """Execute initial Xray latency scan using batched Xray processes for minimal spawn overhead."""
    if not target_pairs:
        return []

    ev = threading.Event()
    if len(target_pairs) == 1 or tries > 1 or requests is None:
        def _single(pair: Tuple[str, int]) -> ScanResult:
            ip, port = pair
            return test_ip(v, ip, port, xray, timeout, tries, url, loglevel, abort_event=ev)

        return _run_concurrent_tasks(target_pairs, _single, concurrency, "scan", on_result=on_result, abort_event=ev)

    results: List[ScanResult] = []
    total = len(target_pairs)
    done = 0
    batch_size = min(max(concurrency, 10), 20)

    for i in range(0, total, batch_size):
        chunk = target_pairs[i : i + batch_size]
        try:
            with BatchXrayProcess(
                xray, v, chunk, loglevel=loglevel, ready_timeout=min(4.0, float(timeout) + 2.0)
            ) as bxp:
                def _probe_batch_item(pair: Tuple[str, int]) -> ScanResult:
                    ip, port = pair
                    if ev.is_set():
                        return ScanResult(ip=ip, port=port, ok=False, error="Aborted")
                    proxies = bxp.get_proxies_for_endpoint(ip, port)
                    if not proxies:
                        return ScanResult(ip=ip, port=port, ok=False, error="Missing SOCKS mapping")
                    try:
                        res, err = _probe_via_proxies(ip, port, proxies, timeout, url)
                        if res is not None:
                            return res
                        return ScanResult(ip=ip, port=port, ok=False, error=err or "Failed")
                    except Exception as exc:
                        logger.debug("Batch probe failed for %s:%d: %s", ip, port, exc)
                        return ScanResult(ip=ip, port=port, ok=False, error=str(exc).split("\n", 1)[0][:160])

                ex = DaemonThreadPoolExecutor(max_workers=min(concurrency, len(chunk)))
                futures = {}
                try:
                    futures = {ex.submit(_probe_batch_item, pair): pair for pair in chunk}
                    for fut in as_completed(futures):
                        try:
                            res = fut.result()
                        except Exception as exc:
                            logger.error("Unhandled batch scan error: %s", exc, exc_info=True)
                            continue
                        results.append(res)
                        done += 1
                        if on_result:
                            try:
                                on_result(res, done, total)
                            except Exception as cb_exc:
                                logger.debug("on_result callback error in scan: %s", cb_exc)
                except KeyboardInterrupt as exc:
                    ev.set()
                    for fut in futures:
                        fut.cancel()
                    terminate_active_xray_processes()
                    ex.shutdown(wait=False, cancel_futures=True)
                    raise ScanInterrupted(results, "scan") from exc
                finally:
                    ex.shutdown(wait=False, cancel_futures=True)
        except ScanInterrupted:
            raise
        except KeyboardInterrupt as exc:
            ev.set()
            terminate_active_xray_processes()
            raise ScanInterrupted(results, "scan") from exc
        except Exception as exc:
            if isinstance(exc, XrayStartupError) and not exc.transient:
                logger.error("Fatal Xray startup error, aborting remaining scan chunks: %s", exc)
                err_msg = str(exc).split("\n", 1)[0][:160]
                for ep_ip, ep_port in target_pairs[i:]:
                    res = ScanResult(ip=ep_ip, port=ep_port, ok=False, error=err_msg)
                    results.append(res)
                    done += 1
                    if on_result:
                        try:
                            on_result(res, done, total)
                        except Exception as cb_exc:
                            logger.debug("on_result callback error in fatal scan abort: %s", cb_exc)
                break
            logger.debug("BatchXrayProcess failed for scan chunk (%s), falling back to individual test_ip", exc)
            try:
                chunk_res = _run_concurrent_tasks(
                    chunk,
                    lambda p: test_ip(v, p[0], p[1], xray, timeout, tries, url, loglevel, abort_event=ev),
                    min(concurrency, len(chunk)),
                    "scan",
                    on_result=lambda r, _d, _t: on_result(r, done + _d, total) if on_result else None,
                    abort_event=ev,
                    prior_results=results,
                )
                results.extend(chunk_res)
                done += len(chunk_res)
            except ScanInterrupted:
                raise

    return results


def build_target_pairs(targets: List[str], ports: List[int]) -> List[Tuple[str, int]]:
    """Expand targets + fallback ports into unique (host, port) endpoint tuples."""
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
    return target_pairs


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
    make_reporter: Optional[Callable[..., Any]] = None,
    on_prefilter_progress: Optional[Callable[[int, int, int], None]] = None,
    make_tcp_reporter: Optional[Callable[[int], Any]] = None,
) -> List[ScanResult]:
    """Execute complete initial scan across targets and ports in a headless, decoupled pipeline."""
    target_pairs = build_target_pairs(targets, ports)
    if not target_pairs:
        return []

    if use_tcp_prefilter and len(target_pairs) > 1:
        if on_stage:
            on_stage("Fast TCP Pre-filter", f"Testing TCP connectivity on {len(target_pairs)} candidate endpoints...", "cyan")
        tcp_workers = min(30, max(10, concurrency))
        tcp_timeout = min(1.5, float(timeout))
        if make_tcp_reporter:
            with make_tcp_reporter(len(target_pairs)) as ui_tcp_cb:
                def _combined_tcp_cb(done: int, total_items: int, alive_count: int) -> None:
                    if ui_tcp_cb:
                        ui_tcp_cb(done, total_items, alive_count)
                    if on_prefilter_progress:
                        on_prefilter_progress(done, total_items, alive_count)

                alive = fast_tcp_filter(
                    target_pairs,
                    timeout=tcp_timeout,
                    workers=tcp_workers,
                    on_progress=_combined_tcp_cb,
                )
        else:
            alive = fast_tcp_filter(
                target_pairs,
                timeout=tcp_timeout,
                workers=tcp_workers,
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

                with DaemonThreadPoolExecutor(max_workers=min(workers, len(chunk))) as ex:
                    list(ex.map(_fetch, chunk))
        except Exception as exc:
            logger.debug("BatchXrayProcess failed for chunk, falling back to concurrent individual resolution: %s", exc)

            def _resolve_single(r: ScanResult) -> None:
                r.colo = resolve_endpoint_colo(v, r.ip, r.port, xray, timeout=timeout)

            with DaemonThreadPoolExecutor(max_workers=min(workers, len(chunk))) as ex:
                list(ex.map(_resolve_single, chunk))


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
    make_reporter: Optional[Callable[..., Any]] = None,
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
    make_reporter: Optional[Callable[..., Any]] = None,
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
    make_reporter: Optional[Callable[..., Any]] = None,
) -> List[ScanResult]:
    """Execute bandwidth download and upload benchmarking with optional UI reporter."""
    if download_mb <= 0 and upload_mb <= 0:
        return candidates
    test_upload = upload_mb > 0
    parts = []
    if download_mb > 0:
        parts.append(f"{download_mb}MB down")
    if test_upload:
        parts.append(f"{upload_mb}MB up")
    if on_stage:
        on_stage("Testing Download & Upload Speed", f"Testing speed on {len(candidates)} endpoints ({', '.join(parts)})...", "magenta")
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


def _save_stage_output(
    results: List[ScanResult],
    output_dir: Path,
    prefix: str,
    v: VlessConfig,
    include_speed_errors: bool = False,
) -> Tuple[List[ScanResult], Path, Path, str]:
    txt, csvp = save_results(results, output_dir, prefix, include_speed_errors=include_speed_errors, vless_config=v)
    return results, txt, csvp, prefix


def execute_configured_post_scan_tests(
    settings: AppSettings,
    v: VlessConfig,
    working_results: List[ScanResult],
    xray: Path,
    output_dir: Path,
    on_stage: Optional[Callable[[str, str, str], None]] = None,
    on_message: Optional[Callable[[str, str], None]] = None,
    make_reporter: Optional[Callable[..., Any]] = None,
    strict_top_targets: bool = False,
) -> Tuple[List[ScanResult], Path, Path, str]:
    """Execute post-scan stability and/or speed testing automatically according to AppSettings."""
    if not working_results:
        return _save_stage_output(working_results, output_dir, "clean_ips", v)

    mode = settings.post_scan_mode
    if mode not in ("full", "stability", "longevity", "speed"):
        enrich_results_with_colo(v, working_results, xray, workers=min(settings.workers, 20), timeout=settings.timeout)
        return _save_stage_output(working_results, output_dir, "clean_ips", v)

    sorted_working = sorted(working_results, key=latency_sort_key)
    top_limit = settings.top_targets
    candidates = sorted_working if (top_limit <= 0 or top_limit >= len(sorted_working)) else sorted_working[:top_limit]
    abort_event = threading.Event()

    # Mode: Full (Stability -> Top Trim -> Anti-Drop -> Speed)
    if mode == "full":
        if top_limit <= 0:
            stability_candidates = sorted_working
        else:
            stab_cap = top_limit if strict_top_targets else max(top_limit, 50)
            stability_candidates = sorted_working[:stab_cap]

        try:
            rechecked = run_stability_stage(
                v, stability_candidates, xray, settings.speed_workers, settings.timeout,
                settings.ping_samples, settings.test_url, on_stage=on_stage, make_reporter=make_reporter,
            )
        except ScanInterrupted as interrupted:
            return _save_stage_output(interrupted.results or stability_candidates, output_dir, "clean_ips_full_interrupted", v)

        survivors = [r for r in rechecked if r.ok and r.packet_loss < 100.0]
        if not survivors:
            if on_message:
                on_message("No endpoints survived stability test.", "yellow")
            return _save_stage_output(rechecked, output_dir, "clean_ips_rechecked", v)

        # Trim to top_targets before slow 30s longevity & speed stages
        ranked_survivors = sorted(survivors, key=recheck_sort_key)
        if top_limit > 0 and len(ranked_survivors) > top_limit:
            ranked_survivors = ranked_survivors[:top_limit]

        if settings.longevity_test:
            try:
                ranked_survivors = run_longevity_stage(
                    v, ranked_survivors, xray, min(settings.speed_workers, 5), settings.longevity_duration,
                    settings.timeout, on_stage=on_stage, make_reporter=make_reporter, abort_event=abort_event,
                )
            except ScanInterrupted as interrupted:
                partial = interrupted.results if interrupted.results else ranked_survivors
                return _save_stage_output(partial, output_dir, "clean_ips_full_interrupted", v)

        try:
            tested = run_speed_stage(
                v, ranked_survivors, xray, settings.speed_workers, settings.speed_duration,
                settings.timeout, settings.download_mb, settings.upload_mb,
                on_stage=on_stage, make_reporter=make_reporter,
            )
        except ScanInterrupted as interrupted:
            partial = interrupted.results if interrupted.results else ranked_survivors
            return _save_stage_output(partial, output_dir, "clean_ips_full_interrupted", v, include_speed_errors=True)

        enrich_results_with_colo(v, tested, xray, workers=settings.speed_workers, timeout=settings.timeout)
        tested = sorted(tested, key=full_sort_key)
        return _save_stage_output(tested, output_dir, "clean_ips_full_tested", v, include_speed_errors=True)

    # Mode: Stability only
    if mode == "stability":
        try:
            rechecked = run_stability_stage(
                v, candidates, xray, settings.speed_workers, settings.timeout,
                settings.ping_samples, settings.test_url, on_stage=on_stage, make_reporter=make_reporter,
            )
        except ScanInterrupted as interrupted:
            return _save_stage_output(interrupted.results or candidates, output_dir, "clean_ips_rechecked_interrupted", v)

        enrich_results_with_colo(v, rechecked, xray, workers=settings.speed_workers, timeout=settings.timeout)
        return _save_stage_output(rechecked, output_dir, "clean_ips_rechecked", v)

    # Mode: Longevity only
    if mode == "longevity":
        try:
            tested = run_longevity_stage(
                v, candidates, xray, min(settings.speed_workers, 5), settings.longevity_duration,
                settings.timeout, on_stage=on_stage, make_reporter=make_reporter, abort_event=abort_event,
            )
        except ScanInterrupted as interrupted:
            return _save_stage_output(interrupted.results or candidates, output_dir, "clean_ips_longevity_interrupted", v)

        enrich_results_with_colo(v, tested, xray, workers=settings.speed_workers, timeout=settings.timeout)
        return _save_stage_output(tested, output_dir, "clean_ips_longevity", v)

    # Mode: Speed only
    try:
        tested = run_speed_stage(
            v, candidates, xray, settings.speed_workers, settings.speed_duration,
            settings.timeout, settings.download_mb, settings.upload_mb,
            on_stage=on_stage, make_reporter=make_reporter,
        )
    except ScanInterrupted as interrupted:
        return _save_stage_output(interrupted.results or candidates, output_dir, "clean_ips_speed_tested_interrupted", v, include_speed_errors=True)

    enrich_results_with_colo(v, tested, xray, workers=settings.speed_workers, timeout=settings.timeout)
    return _save_stage_output(tested, output_dir, "clean_ips_speed_tested", v, include_speed_errors=True)


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
        on_prefilter_progress: Optional[Callable[[int, int, int], None]] = None,
        make_tcp_reporter: Optional[Callable[[int], Any]] = None,
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
            on_prefilter_progress=on_prefilter_progress,
            make_tcp_reporter=make_tcp_reporter,
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
