import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
    DEFAULT_LONGEVITY_DURATION,
    DEFAULT_SPEED_URL,
    DEFAULT_UPLOAD_BYTES,
    DEFAULT_UPLOAD_URL,
    DEFAULT_URL,
    app_dir,
    format_cf_colo,
    parse_cf_colo,
)
from scanner.geoip import enrich_results_with_geoip
from scanner.models import (
    AppSettings,
    ScanInterrupted,
    ScanResult,
    VlessConfig,
)
from scanner.storage import save_results
from scanner.ui.terminal import RICH, console, cprint, render_stage
from scanner.xray import XrayProcess, free_port, make_xray_config, wait_port

try:
    import requests
except ImportError:
    requests = None

try:
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
except ImportError:
    BarColumn = None  # type: ignore
    Progress = None  # type: ignore
    SpinnerColumn = None  # type: ignore
    TextColumn = None  # type: ignore
    TimeElapsedColumn = None  # type: ignore


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
    workers: int = 80,
) -> List[Tuple[str, int]]:
    """Filter candidate endpoints using fast TCP handshake before running Xray."""
    alive: List[Tuple[str, int]] = []
    total = len(target_pairs)
    if total == 0:
        return []
    max_w = min(workers, total)
    if RICH and console is not None and Progress is not None:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TextColumn("[green]Passed: {task.fields[passed]}[/green]"),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task = progress.add_task("TCP Pre-filtering", total=total, passed=0)
            with ThreadPoolExecutor(max_workers=max_w) as ex:
                futures = {ex.submit(check_tcp_port, ip, port, timeout): (ip, port) for ip, port in target_pairs}
                for fut in as_completed(futures):
                    pair = futures[fut]
                    try:
                        if fut.result():
                            alive.append(pair)
                    except Exception:
                        pass
                    progress.update(task, advance=1, passed=len(alive))
    else:
        done = 0
        with ThreadPoolExecutor(max_workers=max_w) as ex:
            futures = {ex.submit(check_tcp_port, ip, port, timeout): (ip, port) for ip, port in target_pairs}
            for fut in as_completed(futures):
                pair = futures[fut]
                try:
                    if fut.result():
                        alive.append(pair)
                except Exception:
                    pass
                done += 1
                print(f"TCP Filter progress: {done}/{total} (Alive: {len(alive)})", end="\r")
        print()
    return alive


def test_ip(
    v: VlessConfig,
    ip: str,
    port: int,
    xray: Path,
    timeout: int,
    tries: int,
    url: str,
    loglevel: str = "warning",
    keep_configs: bool = False,
) -> ScanResult:
    """Test a single IP and port through Xray's local SOCKS proxy."""
    last_error = ""
    for _ in range(max(1, tries)):
        socks_port = free_port()
        temp_dir_obj = tempfile.TemporaryDirectory(prefix="rkh_cfs_")
        temp_dir = Path(temp_dir_obj.name)
        cfg_path = temp_dir / "config.json"
        cfg_path.write_text(
            json.dumps(make_xray_config(v, ip, socks_port, loglevel, port=port), indent=2),
            encoding="utf-8",
        )
        proc = None
        start = time.perf_counter()
        xray_dir = xray.parent
        env = os.environ.copy()
        env["XRAY_LOCATION_ASSET"] = str(xray_dir)
        try:
            proc = subprocess.Popen(
                [str(xray), "run", "-config", str(cfg_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=str(xray_dir),
                env=env,
            )
            if not wait_port(socks_port, min(3.0, float(timeout))):
                last_error = "Xray SOCKS port did not start"
                continue
            if requests is None:
                return ScanResult(ip=ip, port=port, ok=False, error="Python package requests[socks] is not installed")
            proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
            r = requests.get(url, proxies=proxies, timeout=timeout, headers={"User-Agent": f"{APP_HEADER}"})
            latency = (time.perf_counter() - start) * 1000
            if 200 <= r.status_code < 400:
                colo = parse_cf_colo(r.text[:500]) if (r.text and "colo=" in r.text[:500]) else None
                return ScanResult(ip=ip, port=port, ok=True, latency_ms=latency, status_code=r.status_code, colo=colo)
            last_error = f"HTTP {r.status_code}"
        except Exception as exc:
            last_error = str(exc).split("\n", 1)[0][:160]
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            if keep_configs:
                keep_dir = app_dir() / "configs" / "temp"
                keep_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(cfg_path, keep_dir / f"{ip.replace(':', '_')}_{port}_{int(time.time())}.json")
            temp_dir_obj.cleanup()
    return ScanResult(ip=ip, port=port, ok=False, error=last_error or "Failed")


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
    socks_port = free_port()
    temp_dir_obj = tempfile.TemporaryDirectory(prefix="rkh_cfs_speed_")
    temp_dir = Path(temp_dir_obj.name)
    cfg_path = temp_dir / "config.json"
    cfg_path.write_text(
        json.dumps(make_xray_config(v, ip, socks_port, loglevel, port=port), indent=2),
        encoding="utf-8",
    )
    proc = None
    out = ScanResult(
        ip=base_result.ip,
        port=base_result.port,
        ok=base_result.ok,
        latency_ms=base_result.latency_ms,
        status_code=base_result.status_code,
        error=base_result.error,
        speed_mbps=base_result.speed_mbps,
        speed_bytes=base_result.speed_bytes,
        speed_error=base_result.speed_error,
        upload_mbps=base_result.upload_mbps,
        upload_bytes=base_result.upload_bytes,
        upload_error=base_result.upload_error,
        recheck_passed=base_result.recheck_passed,
        recheck_total=base_result.recheck_total,
        packet_loss=base_result.packet_loss,
        jitter_ms=base_result.jitter_ms,
        sustained=base_result.sustained,
        longevity_loss=base_result.longevity_loss,
        colo=base_result.colo,
        ip_country=base_result.ip_country,
        ip_city=base_result.ip_city,
        ip_org=base_result.ip_org,
    )
    xray_dir = xray.parent
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(xray_dir)
    try:
        proc = subprocess.Popen(
            [str(xray), "run", "-config", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(xray_dir),
            env=env,
        )
        if not wait_port(socks_port, min(3.0, float(timeout))):
            out.speed_error = "Xray SOCKS port did not start"
            return out
        if requests is None:
            out.speed_error = "Python package requests[socks] is not installed"
            return out
        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}

        # 1. Download Speed Test
        if speed_bytes > 0:
            url = speed_url_template.format(bytes=speed_bytes)
            downloaded = 0
            start = time.perf_counter()
            with requests.get(url, proxies=proxies, timeout=timeout, stream=True, headers={"User-Agent": f"{APP_HEADER}"}) as r:
                if not (200 <= r.status_code < 400):
                    out.speed_error = f"HTTP {r.status_code}"
                else:
                    for chunk in r.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        downloaded += len(chunk)
                        if downloaded >= speed_bytes:
                            break
                        if speed_duration > 0 and (time.perf_counter() - start) >= speed_duration:
                            break
                    elapsed = max(time.perf_counter() - start, 0.001)
                    out.speed_bytes = downloaded
                    out.speed_mbps = (downloaded * 8) / elapsed / 1_000_000
                    out.speed_error = ""

        # 2. Upload Speed Test
        if test_upload and upload_bytes > 0:
            try:
                upload_payload = b"0" * min(upload_bytes, 10 * 1024 * 1024)
                up_start = time.perf_counter()
                up_timeout = max(timeout, speed_duration + 5 if speed_duration > 0 else 10)
                with requests.post(upload_url, data=upload_payload, proxies=proxies, timeout=up_timeout, headers={"User-Agent": f"{APP_HEADER}"}) as up_res:
                    if 200 <= up_res.status_code < 400:
                        up_elapsed = max(time.perf_counter() - up_start, 0.001)
                        out.upload_bytes = len(upload_payload)
                        out.upload_mbps = (len(upload_payload) * 8) / up_elapsed / 1_000_000
                        out.upload_error = ""
                    else:
                        out.upload_error = f"HTTP {up_res.status_code}"
            except Exception as up_exc:
                out.upload_error = str(up_exc).split("\n", 1)[0][:160]

        return out
    except Exception as exc:
        err_msg = str(exc).split("\n", 1)[0][:160]
        if not out.speed_error and out.speed_mbps is None:
            out.speed_error = err_msg
        if test_upload and not out.upload_error and out.upload_mbps is None:
            out.upload_error = err_msg
        return out
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        temp_dir_obj.cleanup()


def run_speed_tests(
    v: VlessConfig,
    ok_results: List[ScanResult],
    xray: Path,
    workers: int,
    timeout: int,
    speed_bytes: int,
    speed_duration: int,
    speed_url_template: str,
    loglevel: str = "warning",
    test_upload: bool = True,
    upload_bytes: int = DEFAULT_UPLOAD_BYTES,
    upload_url: str = DEFAULT_UPLOAD_URL,
) -> List[ScanResult]:
    targets = [r for r in ok_results if r.ok]
    if not targets:
        return []
    results: List[ScanResult] = []
    mb_down = speed_bytes / 1024 / 1024
    mb_up = (upload_bytes / 1024 / 1024) if test_upload else 0
    up_info = f" + {mb_up:.1f}MB upload" if test_upload and mb_up > 0 else ""
    if RICH and console is not None and Progress is not None:
        duration_text = f" | up to {speed_duration}s per IP" if speed_duration > 0 else ""
        title = f"Speed testing: {mb_down:.1f}MB download{up_info} per IP{duration_text}"
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold yellow]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task = progress.add_task(title, total=len(targets))
            ex = ThreadPoolExecutor(max_workers=workers)
            futures = {}
            try:
                futures = {
                    ex.submit(
                        speed_test_ip,
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
                    ): r.endpoint
                    for r in targets
                }
                for fut in as_completed(futures):
                    r = fut.result()
                    results.append(r)
                    down_str = f"↓ {r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "↓ -"
                    if test_upload:
                        up_str = f"↑ {r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "↑ -"
                        if r.speed_mbps is not None or r.upload_mbps is not None:
                            console.print(f"[bright_green]SPD[/bright_green] {r.endpoint:<38} [bold]{down_str}[/bold] | [bold cyan]{up_str}[/bold cyan]")
                        else:
                            err = r.speed_error or r.upload_error or "failed"
                            console.print(f"[yellow]SPD-FAIL[/yellow] {r.endpoint:<38} {err}")
                    else:
                        if r.speed_mbps is not None:
                            console.print(f"[bright_green]SPD[/bright_green] {r.endpoint:<45} [bold]{down_str}[/bold]")
                        else:
                            console.print(f"[yellow]SPD-FAIL[/yellow] {r.endpoint:<41} {r.speed_error}")
                    progress.advance(task)
            except KeyboardInterrupt:
                for fut in futures:
                    fut.cancel()
                ex.shutdown(wait=False, cancel_futures=True)
                raise ScanInterrupted(results, "speed test")
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
    else:
        done = 0
        ex = ThreadPoolExecutor(max_workers=workers)
        futures = {}
        try:
            futures = {
                ex.submit(
                    speed_test_ip,
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
                ): r.endpoint
                for r in targets
            }
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                done += 1
                down_str = f"↓ {r.speed_mbps:.2f} Mbps" if r.speed_mbps is not None else "↓ -"
                if test_upload:
                    up_str = f"↑ {r.upload_mbps:.2f} Mbps" if r.upload_mbps is not None else "↑ -"
                    print(f"SPD {r.endpoint:<38} {down_str} | {up_str}")
                else:
                    print(f"SPD {r.endpoint:<45} {down_str}")
                print(f"Speed progress: {done}/{len(targets)}", end="\r")
            print()
        except KeyboardInterrupt:
            for fut in futures:
                fut.cancel()
            ex.shutdown(wait=False, cancel_futures=True)
            raise ScanInterrupted(results, "speed test")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
    return sorted(results, key=speed_sort_key)


def summarize_latency(samples: List[ScanResult]) -> ScanResult:
    ok_samples = [r for r in samples if r.ok and r.latency_ms is not None]
    ip = samples[0].ip if samples else ""
    port = samples[0].port if samples else 443
    total = len(samples)
    passed = len(ok_samples)
    if not ok_samples:
        err = samples[-1].error if samples else "No samples"
        return ScanResult(ip=ip, port=port, ok=False, error=err, recheck_passed=0, recheck_total=total, packet_loss=100.0, jitter_ms=None)
    avg = sum(r.latency_ms or 0 for r in ok_samples) / passed
    if passed > 1:
        jitter = sum(abs((r.latency_ms or avg) - avg) for r in ok_samples) / passed
    else:
        jitter = 0.0
    packet_loss = ((total - passed) / total) * 100.0 if total > 0 else 0.0
    status = ok_samples[-1].status_code
    colo = next((s.colo for s in ok_samples if s.colo), None)
    return ScanResult(
        ip=ip,
        port=port,
        ok=True,
        latency_ms=avg,
        status_code=status,
        error=f"{passed}/{total} ok (loss: {packet_loss:.0f}%, jit: {jitter:.1f}ms)",
        recheck_passed=passed,
        recheck_total=total,
        packet_loss=packet_loss,
        jitter_ms=jitter,
        colo=colo,
        ip_country=next((s.ip_country for s in ok_samples if s.ip_country), None),
        ip_city=next((s.ip_city for s in ok_samples if s.ip_city), None),
        ip_org=next((s.ip_org for s in ok_samples if s.ip_org), None),
    )


def retest_ip_latency(
    v: VlessConfig,
    target: ScanResult,
    xray: Path,
    timeout: int,
    sample_count: int,
    url: str,
    loglevel: str = "warning",
) -> ScanResult:
    samples: List[ScanResult] = []
    for _ in range(max(1, sample_count)):
        samples.append(test_ip(v, target.ip, target.port, xray, timeout, 1, url, loglevel, False))
    return summarize_latency(samples)


def run_latency_recheck(
    v: VlessConfig,
    ok_results: List[ScanResult],
    xray: Path,
    workers: int,
    timeout: int,
    sample_count: int,
    url: str,
    loglevel: str = "warning",
) -> List[ScanResult]:
    targets = sorted(ok_results, key=lambda r: r.latency_ms or 10**9)
    if not targets:
        return []
    results: List[ScanResult] = []
    if RICH and console is not None and Progress is not None:
        title = f"Re-checking stability: {sample_count} real Xray test(s) per IP"
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold magenta]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task = progress.add_task(title, total=len(targets))
            ex = ThreadPoolExecutor(max_workers=workers)
            futures = {}
            try:
                futures = {ex.submit(retest_ip_latency, v, t, xray, timeout, sample_count, url, loglevel): t.endpoint for t in targets}
                for fut in as_completed(futures):
                    r = fut.result()
                    results.append(r)
                    results.sort(key=recheck_sort_key)
                    if r.ok:
                        jit_txt = f"  jit: [cyan]{r.jitter_ms:.1f}ms[/cyan]" if r.jitter_ms is not None else ""
                        loss_txt = f"  loss: [yellow]{r.packet_loss:.0f}%[/yellow]" if r.packet_loss > 0 else "  loss: [green]0%[/green]"
                        console.print(f"[bright_green]RE-OK[/bright_green] {r.endpoint:<38} [bold]{r.latency_ms:.1f} ms avg[/bold]{jit_txt}{loss_txt}  pass {r.recheck_passed}/{r.recheck_total}")
                    else:
                        console.print(f"[red]DROP[/red]  {r.endpoint:<38} {r.error}")
                    progress.advance(task)
            except KeyboardInterrupt:
                for fut in futures:
                    fut.cancel()
                ex.shutdown(wait=False, cancel_futures=True)
                raise ScanInterrupted(results, "latency re-check")
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
    else:
        done = 0
        ex = ThreadPoolExecutor(max_workers=workers)
        futures = {}
        try:
            futures = {ex.submit(retest_ip_latency, v, t, xray, timeout, sample_count, url, loglevel): t.endpoint for t in targets}
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                done += 1
                results.sort(key=recheck_sort_key)
                if r.ok:
                    jit_txt = f" jit: {r.jitter_ms:.1f}ms" if r.jitter_ms is not None else ""
                    loss_txt = f" loss: {r.packet_loss:.0f}%"
                    print(f"RE-OK {r.endpoint:<38} {r.latency_ms:.1f} ms avg{jit_txt}{loss_txt} pass {r.recheck_passed}/{r.recheck_total}")
                print(f"Re-check progress: {done}/{len(targets)}", end="\r")
            print()
        except KeyboardInterrupt:
            for fut in futures:
                fut.cancel()
            ex.shutdown(wait=False, cancel_futures=True)
            raise ScanInterrupted(results, "latency re-check")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
    return sorted(results, key=recheck_sort_key)


def longevity_test_ip(
    v: VlessConfig,
    base_result: ScanResult,
    xray: Path,
    duration: int = DEFAULT_LONGEVITY_DURATION,
    interval: float = 2.5,
    timeout: int = 3,
    url: str = DEFAULT_URL,
    loglevel: str = "warning",
) -> ScanResult:
    """Test connection endurance (Anti-Drop) through Xray over a sustained duration window.

    Verifies that the endpoint does not get throttled, disconnected, or reset (TCP RST)
    by ISP DPI firewalls after several seconds of active traffic.
    """
    ip = base_result.ip
    port = base_result.port
    socks_port = free_port()
    temp_dir_obj = tempfile.TemporaryDirectory(prefix="rkh_cfs_long_")
    temp_dir = Path(temp_dir_obj.name)
    cfg_path = temp_dir / "config.json"
    cfg_path.write_text(
        json.dumps(make_xray_config(v, ip, socks_port, loglevel, port=port), indent=2),
        encoding="utf-8",
    )
    proc = None
    out = ScanResult(
        ip=base_result.ip,
        port=base_result.port,
        ok=base_result.ok,
        latency_ms=base_result.latency_ms,
        status_code=base_result.status_code,
        error=base_result.error,
        speed_mbps=base_result.speed_mbps,
        speed_bytes=base_result.speed_bytes,
        speed_error=base_result.speed_error,
        upload_mbps=base_result.upload_mbps,
        upload_bytes=base_result.upload_bytes,
        upload_error=base_result.upload_error,
        recheck_passed=base_result.recheck_passed,
        recheck_total=base_result.recheck_total,
        packet_loss=base_result.packet_loss,
        jitter_ms=base_result.jitter_ms,
        sustained=False,
        longevity_loss=100.0,
        colo=base_result.colo,
        ip_country=base_result.ip_country,
        ip_city=base_result.ip_city,
        ip_org=base_result.ip_org,
    )
    xray_dir = xray.parent
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(xray_dir)
    try:
        proc = subprocess.Popen(
            [str(xray), "run", "-config", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(xray_dir),
            env=env,
        )
        if not wait_port(socks_port, min(3.0, float(timeout))):
            out.error = "Xray SOCKS port did not start"
            out.sustained = False
            out.longevity_loss = 100.0
            return out

        if requests is None:
            out.error = "Python package requests[socks] is not installed"
            out.sustained = False
            out.longevity_loss = 100.0
            return out

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
        total_probes = 0
        passed_probes = 0
        start_time = time.perf_counter()
        headers = {"User-Agent": APP_HEADER}

        with requests.Session() as session:
            session.proxies = proxies
            while True:
                probe_start = time.perf_counter()
                total_probes += 1
                try:
                    r = session.get(url, timeout=timeout, headers=headers)
                    if 200 <= r.status_code < 400:
                        passed_probes += 1
                except Exception:
                    pass

                now = time.perf_counter()
                if (now - start_time) >= duration:
                    break

                probe_time = now - probe_start
                sleep_time = max(0.1, interval - probe_time)
                if (now + sleep_time - start_time) > duration:
                    sleep_time = max(0.1, duration - (now - start_time))
                time.sleep(sleep_time)

        loss = ((total_probes - passed_probes) / total_probes * 100.0) if total_probes > 0 else 100.0
        out.longevity_loss = loss
        out.sustained = (passed_probes == total_probes) and (total_probes > 0)
        if not out.sustained:
            out.error = f"DPI dropped {total_probes - passed_probes}/{total_probes} probes ({loss:.0f}% loss over {duration}s)"
        return out
    except Exception as exc:
        out.sustained = False
        out.longevity_loss = 100.0
        out.error = str(exc).split("\n", 1)[0][:160]
        return out
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        temp_dir_obj.cleanup()


def run_longevity_tests(
    v: VlessConfig,
    ok_results: List[ScanResult],
    xray: Path,
    workers: int = 5,
    duration: int = DEFAULT_LONGEVITY_DURATION,
    timeout: int = 3,
    url: str = DEFAULT_URL,
    loglevel: str = "warning",
) -> List[ScanResult]:
    """Run sustained endurance (Anti-Drop) tests concurrently across endpoints."""
    targets = [r for r in ok_results if r.ok]
    if not targets:
        return []
    results: List[ScanResult] = []
    concurrency = min(workers, len(targets))

    if RICH and console is not None and Progress is not None:
        title = f"Anti-Drop Testing: {duration}s DPI endurance per IP"
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold green]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task = progress.add_task(title, total=len(targets))
            ex = ThreadPoolExecutor(max_workers=concurrency)
            futures = {}
            try:
                futures = {
                    ex.submit(
                        longevity_test_ip,
                        v,
                        r,
                        xray,
                        duration,
                        2.5,
                        timeout,
                        url,
                        loglevel,
                    ): r.endpoint
                    for r in targets
                }
                for fut in as_completed(futures):
                    r = fut.result()
                    results.append(r)
                    if r.sustained:
                        console.print(
                            f"[bright_green]SUSTAINED[/bright_green] {r.endpoint:<38} [green]🛡️ 0% drop ({duration}s endurance)[/green]"
                        )
                    else:
                        console.print(
                            f"[yellow]DPI-DROP[/yellow]  {r.endpoint:<38} [red]⚠️ {r.longevity_loss:.0f}% drop over {duration}s[/red]"
                        )
                    progress.advance(task)
            except KeyboardInterrupt:
                for fut in futures:
                    fut.cancel()
                ex.shutdown(wait=False, cancel_futures=True)
                raise ScanInterrupted(results, "anti-drop test")
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
    else:
        done = 0
        ex = ThreadPoolExecutor(max_workers=concurrency)
        futures = {}
        try:
            futures = {
                ex.submit(
                    longevity_test_ip,
                    v,
                    r,
                    xray,
                    duration,
                    2.5,
                    timeout,
                    url,
                    loglevel,
                ): r.endpoint
                for r in targets
            }
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                done += 1
                if r.sustained:
                    print(f"SUSTAINED {r.endpoint:<38} 🛡️ 0% drop ({duration}s)")
                else:
                    print(f"DPI-DROP  {r.endpoint:<38} ⚠️ {r.longevity_loss:.0f}% drop")
                print(f"Anti-Drop progress: {done}/{len(targets)}", end="\r")
            print()
        except KeyboardInterrupt:
            for fut in futures:
                fut.cancel()
            ex.shutdown(wait=False, cancel_futures=True)
            raise ScanInterrupted(results, "anti-drop test")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

    return sorted(results, key=longevity_sort_key)


def run_scan(
    v: VlessConfig,
    targets: List[str],
    ports: List[int],
    xray: Path,
    concurrency: int,
    timeout: int,
    tries: int = 1,
    url: str = "https://cp.cloudflare.com/generate_204",
    loglevel: str = "warning",
    keep_configs: bool = False,
    use_tcp_prefilter: bool = True,
) -> List[ScanResult]:
    """Execute complete initial scan across targets and ports."""
    target_pairs: List[Tuple[str, int]] = [(ip, p) for ip in targets for p in ports]
    if not target_pairs:
        return []

    if use_tcp_prefilter and len(target_pairs) > 1:
        render_stage("Fast TCP Pre-filter", f"Testing TCP connectivity on {len(target_pairs)} candidate endpoints...", "cyan")
        alive = fast_tcp_filter(target_pairs, timeout=min(1.5, float(timeout)), workers=min(80, max(20, concurrency * 3)))
        if alive:
            cprint(f"TCP pre-filter passed: {len(alive)} / {len(target_pairs)} endpoints", "green")
            target_pairs = alive
        else:
            cprint("No endpoints passed TCP pre-filter. Testing all endpoints directly with Xray...", "yellow")

    results: List[ScanResult] = []
    render_stage("Xray Latency Scan", f"Testing {len(target_pairs)} endpoint(s) with Xray...", "cyan")
    if RICH and console is not None and Progress is not None:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        )
        with progress:
            task = progress.add_task("Scanning", total=len(target_pairs))
            ex = ThreadPoolExecutor(max_workers=concurrency)
            futures = {}
            try:
                futures = {ex.submit(test_ip, v, ip, p, xray, timeout, tries, url, loglevel, keep_configs): (ip, p) for ip, p in target_pairs}
                for fut in as_completed(futures):
                    r = fut.result()
                    results.append(r)
                    if r.ok:
                        console.print(f"[green]OK[/green]  {r.endpoint:<45} [bold]{r.latency_ms:.1f} ms[/bold]  HTTP {r.status_code}")
                    progress.advance(task)
            except KeyboardInterrupt:
                for fut in futures:
                    fut.cancel()
                ex.shutdown(wait=False, cancel_futures=True)
                raise ScanInterrupted(results, "scan")
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
    else:
        done = 0
        ex = ThreadPoolExecutor(max_workers=concurrency)
        futures = {}
        try:
            futures = {ex.submit(test_ip, v, ip, p, xray, timeout, tries, url, loglevel, keep_configs): (ip, p) for ip, p in target_pairs}
            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                done += 1
                if r.ok:
                    print(f"OK {r.endpoint:<45} {r.latency_ms:.1f} ms HTTP {r.status_code}")
                print(f"Progress: {done}/{len(target_pairs)}", end="\r")
            print()
        except KeyboardInterrupt:
            for fut in futures:
                fut.cancel()
            ex.shutdown(wait=False, cancel_futures=True)
            raise ScanInterrupted(results, "scan")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
    return results


def resolve_endpoint_colo(
    v: VlessConfig,
    ip: str,
    port: int,
    xray: Path,
    timeout: int = 3,
) -> Optional[str]:
    """Query https://cloudflare.com/cdn-cgi/trace via Xray proxy to detect Cloudflare edge PoP (Colo)."""
    socks_port = free_port()
    temp_dir_obj = tempfile.TemporaryDirectory(prefix="rkh_cfs_colo_")
    temp_dir = Path(temp_dir_obj.name)
    cfg_path = temp_dir / "config.json"
    cfg_path.write_text(
        json.dumps(make_xray_config(v, ip, socks_port, "warning", port=port), indent=2),
        encoding="utf-8",
    )
    proc = None
    xray_dir = xray.parent
    env = os.environ.copy()
    env["XRAY_LOCATION_ASSET"] = str(xray_dir)
    try:
        proc = subprocess.Popen(
            [str(xray), "run", "-config", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=str(xray_dir),
            env=env,
        )
        if not wait_port(socks_port, min(3.0, float(timeout))):
            return None
        if requests is None:
            return None
        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
        r = requests.get(CF_TRACE_URL, proxies=proxies, timeout=timeout, headers={"User-Agent": f"{APP_HEADER}"})
        if 200 <= r.status_code < 400 and r.text:
            return parse_cf_colo(r.text)
        return None
    except Exception:
        return None
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        temp_dir_obj.cleanup()


def enrich_results_with_colo(
    v: VlessConfig,
    results: List[ScanResult],
    xray: Path,
    workers: int = 10,
    timeout: int = 3,
) -> None:
    """Concurrently resolve Cloudflare edge colo airport code and physical IP GeoIP location."""
    enrich_results_with_geoip(results, workers=workers, timeout=timeout)
    targets = [r for r in results if r.ok and not r.colo]
    if not targets:
        return
    max_w = min(max(1, workers), len(targets))
    with ThreadPoolExecutor(max_workers=max_w) as ex:
        futures = {ex.submit(resolve_endpoint_colo, v, r.ip, r.port, xray, timeout): r for r in targets}
        for fut in as_completed(futures):
            res = futures[fut]
            try:
                colo = fut.result()
                if colo:
                    res.colo = colo
            except Exception:
                pass


def execute_configured_post_scan_tests(
    settings: AppSettings,
    v: VlessConfig,
    working_results: List[ScanResult],
    xray: Path,
    output_dir: Path,
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
    if settings.top_targets <= 0 or settings.top_targets >= len(sorted_working):
        candidates = sorted_working
    else:
        candidates = sorted_working[: settings.top_targets]

    # Mode: Full (Stability + Speed)
    if settings.post_scan_mode == "full":
        render_stage(
            "Testing Stability & Jitter",
            f"Testing {len(candidates)} endpoints ({settings.ping_samples} pings each)...",
            "magenta",
        )
        try:
            rechecked = run_latency_recheck(
                v,
                candidates,
                xray,
                settings.speed_workers,
                settings.timeout,
                settings.ping_samples,
                settings.test_url,
                "warning",
            )
        except ScanInterrupted as interrupted:
            rechecked = interrupted.results
            txt, csvp = save_results(rechecked, output_dir, "clean_ips_full_interrupted", vless_config=v)
            return rechecked, txt, csvp, "clean_ips_full_interrupted"

        survivors = [r for r in rechecked if r.ok and r.packet_loss < 100.0]
        if not survivors:
            cprint("No endpoints survived stability test.", "yellow")
            txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked", vless_config=v)
            return rechecked, txt, csvp, "clean_ips_rechecked"

        # Anti-Drop (Longevity) testing if enabled
        if settings.longevity_test:
            render_stage(
                "Testing Anti-Drop (DPI Endurance)",
                f"Testing sustained connection on {len(survivors)} endpoints ({settings.longevity_duration}s continuous)...",
                "green",
                clear=False,
            )
            try:
                survivors = run_longevity_tests(
                    v,
                    survivors,
                    xray,
                    workers=min(settings.speed_workers, 5),
                    duration=settings.longevity_duration,
                    timeout=settings.timeout,
                    url=settings.test_url,
                )
            except ScanInterrupted as interrupted:
                survivors = interrupted.results
                txt, csvp = save_results(survivors, output_dir, "clean_ips_full_interrupted", vless_config=v)
                return survivors, txt, csvp, "clean_ips_full_interrupted"

        up_text = f", {settings.upload_mb}MB up" if settings.upload_mb > 0 else ""
        render_stage(
            "Testing Download & Upload Speed",
            f"Testing speed on {len(survivors)} surviving endpoints ({settings.download_mb}MB down{up_text})...",
            "magenta",
            clear=False,
        )
        try:
            tested = run_speed_tests(
                v,
                survivors,
                xray,
                settings.speed_workers,
                max(settings.timeout, settings.speed_duration + 10),
                settings.download_mb * 1024 * 1024,
                settings.speed_duration,
                DEFAULT_SPEED_URL,
                "warning",
                test_upload=(settings.upload_mb > 0),
                upload_bytes=settings.upload_mb * 1024 * 1024,
                upload_url=DEFAULT_UPLOAD_URL,
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
        render_stage(
            "Testing Stability & Jitter",
            f"Testing {len(candidates)} endpoints ({settings.ping_samples} pings each)...",
            "magenta",
        )
        try:
            rechecked = run_latency_recheck(
                v,
                candidates,
                xray,
                settings.speed_workers,
                settings.timeout,
                settings.ping_samples,
                settings.test_url,
                "warning",
            )
        except ScanInterrupted as interrupted:
            rechecked = interrupted.results
            txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked_interrupted", vless_config=v)
            return rechecked, txt, csvp, "clean_ips_rechecked_interrupted"

        if settings.longevity_test:
            survivors = [r for r in rechecked if r.ok and r.packet_loss < 100.0]
            if survivors:
                render_stage(
                    "Testing Anti-Drop (DPI Endurance)",
                    f"Testing sustained connection on {len(survivors)} endpoints ({settings.longevity_duration}s continuous)...",
                    "green",
                    clear=False,
                )
                try:
                    rechecked = run_longevity_tests(
                        v,
                        survivors,
                        xray,
                        workers=min(settings.speed_workers, 5),
                        duration=settings.longevity_duration,
                        timeout=settings.timeout,
                        url=settings.test_url,
                    )
                except ScanInterrupted as interrupted:
                    rechecked = interrupted.results
                    txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked_interrupted", vless_config=v)
                    return rechecked, txt, csvp, "clean_ips_rechecked_interrupted"

        enrich_results_with_colo(v, rechecked, xray, workers=settings.speed_workers, timeout=settings.timeout)
        txt, csvp = save_results(rechecked, output_dir, "clean_ips_rechecked", vless_config=v)
        return rechecked, txt, csvp, "clean_ips_rechecked"

    # Mode: Longevity / Anti-Drop only
    elif settings.post_scan_mode == "longevity":
        render_stage(
            "Testing Anti-Drop (DPI Endurance)",
            f"Testing sustained connection on {len(candidates)} endpoints ({settings.longevity_duration}s continuous)...",
            "green",
        )
        try:
            tested = run_longevity_tests(
                v,
                candidates,
                xray,
                workers=min(settings.speed_workers, 5),
                duration=settings.longevity_duration,
                timeout=settings.timeout,
                url=settings.test_url,
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
        up_text = f", {settings.upload_mb}MB up" if settings.upload_mb > 0 else ""
        render_stage(
            "Testing Download & Upload Speed",
            f"Testing speed on {len(candidates)} endpoints ({settings.download_mb}MB down{up_text})...",
            "magenta",
        )
        try:
            tested = run_speed_tests(
                v,
                candidates,
                xray,
                settings.speed_workers,
                max(settings.timeout, settings.speed_duration + 10),
                settings.download_mb * 1024 * 1024,
                settings.speed_duration,
                DEFAULT_SPEED_URL,
                "warning",
                test_upload=(settings.upload_mb > 0),
                upload_bytes=settings.upload_mb * 1024 * 1024,
                upload_url=DEFAULT_UPLOAD_URL,
            )
            enrich_results_with_colo(v, tested, xray, workers=settings.speed_workers, timeout=settings.timeout)
            txt, csvp = save_results(tested, output_dir, "clean_ips_speed_tested", include_speed_errors=True, vless_config=v)
            return tested, txt, csvp, "clean_ips_speed_tested"
        except ScanInterrupted as interrupted:
            tested = interrupted.results
            txt, csvp = save_results(tested, output_dir, "clean_ips_speed_tested_interrupted", include_speed_errors=True, vless_config=v)
            return tested, txt, csvp, "clean_ips_speed_tested_interrupted"

    # Fallback
    enrich_results_with_colo(v, working_results, xray, workers=min(settings.workers, 20), timeout=settings.timeout)
    txt, csvp = save_results(working_results, output_dir, "clean_ips", vless_config=v)
    return working_results, txt, csvp, "clean_ips"


class ScannerEngine:
    """Core scanning and diagnostic engine for Cloudflare clean IPs."""

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
        concurrency: int = 66,
        timeout: int = 2,
        url: str = "https://cp.cloudflare.com/generate_204",
        use_tcp_prefilter: bool = True,
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
        )

    def recheck(
        self,
        vless: VlessConfig,
        results: List[ScanResult],
        sample_count: int = 5,
        workers: int = 10,
        timeout: int = 2,
        url: str = "https://cp.cloudflare.com/generate_204",
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
        )

    def test_longevity(
        self,
        vless: VlessConfig,
        results: List[ScanResult],
        duration: int = DEFAULT_LONGEVITY_DURATION,
        workers: int = 5,
        timeout: int = 3,
        url: str = DEFAULT_URL,
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
            url=url,
        )

    def test_speed(
        self,
        vless: VlessConfig,
        results: List[ScanResult],
        download_mb: int = 5,
        upload_mb: int = 1,
        duration: int = 5,
        workers: int = 5,
    ) -> List[ScanResult]:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        return run_speed_tests(
            v=vless,
            ok_results=results,
            xray=self.xray_path,
            workers=workers,
            timeout=duration + 10,
            speed_bytes=download_mb * 1024 * 1024,
            speed_duration=duration,
            speed_url_template=DEFAULT_SPEED_URL,
            test_upload=(upload_mb > 0),
            upload_bytes=upload_mb * 1024 * 1024,
        )

    def resolve_colo(self, vless: VlessConfig, ip: str, port: int, timeout: int = 3) -> Optional[str]:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        return resolve_endpoint_colo(vless, ip, port, self.xray_path, timeout=timeout)

    def enrich_colo(self, vless: VlessConfig, results: List[ScanResult], workers: int = 10, timeout: int = 3) -> None:
        if not self.xray_path:
            raise FileNotFoundError("Xray executable not found")
        enrich_results_with_colo(vless, results, self.xray_path, workers=workers, timeout=timeout)

