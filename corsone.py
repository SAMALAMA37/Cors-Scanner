#!/usr/bin/env python3
"""
CorsOne v2.0 - CORS Misconfiguration Discovery Tool (insane-speed rewrite)

Built for huge lists of bare domains, one per line:

    sub.example.com
    sub2.example2.com

Usage:
    python3 corsone.py -u https://example.com
    python3 corsone.py -l domains.txt
    python3 corsone.py -l domains.txt -w 300 --per-host 25
    python3 corsone.py -l domains.txt --fast -vo -o found -f jsonl
    cat domains.txt | python3 corsone.py -w 200

Speed model:
    * one shared aiohttp session (keep-alive, DNS cache, aiodns resolver)
    * a single global worker pool shared across ALL targets (producer/
      consumer queue) - no more "one URL at a time" batching
    * optional live-probe phase removes dead hosts BEFORE payload testing
      (each dead host would otherwise burn ~70 requests)
    * automatic https -> http fallback for scheme-less domains
    * streaming output (txt / jsonl) keeps memory flat on million-line lists
    * connection-level retries with exponential backoff

Version: 2.0.0
Based on CorsOne v1.1.0 by Mohammad Reza Omrani (MIT)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

import aiohttp
import validators
from aiohttp import ClientTimeout, TCPConnector
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

logger = logging.getLogger(__name__)


def _setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """Configure module logging to stderr (and optionally a file)."""
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    if logger.handlers:
        logger.handlers.clear()
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    if log_file:
        try:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError as e:
            logger.warning(f"Could not create log file: {e}")


def _pick_event_loop_policy() -> None:
    """aiodns (c-ares) requires a selector event loop on Windows."""
    if sys.platform.startswith('win'):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except AttributeError:
            pass


# ============================================================================
# Data classes
# ============================================================================

@dataclass
class ScanResult:
    """Represents a single CORS bypass test result."""
    url: str
    bypass_name: str
    bypass_value: str
    is_vulnerable: bool
    response_code: int = 0
    acac: Optional[str] = None
    acao: Optional[str] = None
    error: Optional[str] = None
    severity: str = ""             # CRITICAL | HIGH | MEDIUM | LOW | "" (none)
    reflected: bool = False        # stage-1: origin reflected (creds unknown)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary (None/empty fields stripped)."""
        raw = asdict(self)
        return {k: v for k, v in raw.items() if v is not None and v != ""}

    def __str__(self) -> str:
        """String representation."""
        if self.is_vulnerable:
            status = f'[VULNERABLE][{self.severity or "UNKNOWN"}]'
        elif self.reflected:
            status = '[REFLECTED][LOW]'   # stage-1 regex break, no creds (yet)
        elif self.error:
            status = '[ERROR]'
        else:
            status = '[SAFE]'
        line = f"{self.url} {status} {self.bypass_name}: {self.bypass_value}"
        return f"{line} ({self.error})" if self.error else line


@dataclass
class Target:
    """A target line after normalization."""
    raw: str
    host: str
    provisional_url: str
    explicit_scheme: Optional[str]  # None -> bare domain (probe picks scheme)


@dataclass
class ScanConfig:
    """Configuration for CORS vulnerability scanning."""
    url: str = ""
    method: str = "GET"
    custom_domain: str = "attacker.com"
    rate_limit: float = 0.0
    timeout: int = 8
    retries: int = 1
    backoff_factor: float = 0.3
    max_workers: int = 200
    per_host: int = 25
    stop_on_first: bool = False
    no_color: bool = False
    output_file: Optional[str] = None
    output_format: str = "txt"
    output_log: Optional[str] = None
    custom_headers: Optional[Dict[str, str]] = None
    proxy: Optional[Dict[str, str]] = None
    verbose: bool = False
    vulnerable_only: bool = False
    probe: bool = True             # live-probe hosts first, skip dead ones
    scheme: str = "auto"           # auto | https | http (for bare domains)
    show_safe: bool = False
    quiet: bool = False
    fast: bool = False             # curated payload subset only
    progress_interval: float = 2.0
    severity_filter: str = "LOW"   # lowest layer to show: CRITICAL|HIGH|MEDIUM|LOW


# ============================================================================
# Severity classification
# ============================================================================

#: ordered from worst to least severe (rank index: lower == worse)
SEVERITY_ORDER: List[str] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
SEVERITY_RANK: Dict[str, int] = {n: i for i, n in enumerate(SEVERITY_ORDER)}

#: severity per bypass category
#:   CRITICAL - arbitrary origin trusted WITH credentials (instant account theft)
#:   HIGH     - origin suffix/prefix breaks, TLS downgrade, localhost regex
#:   MEDIUM   - subdomain trust + wildcard/regexp-combo breaks
#:   LOW      - stage-1 regex break: origin reflected but WITHOUT credentials
SEVERITY_BY_NAME: Dict[str, str] = {
    'Reflected Origin': 'CRITICAL',
    'Null Origin': 'CRITICAL',
    'Breaking TLS': 'HIGH',
    'Domain ends allow': 'HIGH',
    'Unencrypted domain ends allow': 'HIGH',
    'Localhost regex': 'HIGH',
    'Unencrypted localhost regex': 'HIGH',
    'Bypass 1': 'HIGH',
    'Bypass 2': 'HIGH',
    'Bypass 18': 'HIGH',
    'Trusted Subdomains': 'MEDIUM',
    'Unencrypted Subdomains': 'MEDIUM',
}


def classify_severity(bypass_name: str, is_vulnerable: bool,
                      reflected: bool) -> str:
    """Map a bypass result to its severity layer."""
    if is_vulnerable:
        return SEVERITY_BY_NAME.get(bypass_name, 'MEDIUM')
    if reflected:
        return 'LOW'  # stage-1 regex break: filter broken, no creds yet
    return ''


def severity_rank(name: str) -> int:
    """Rank of a severity name (unknown names rank as MEDIUM)."""
    return SEVERITY_RANK.get(name.strip().upper(), SEVERITY_RANK['MEDIUM'])


def parse_severity_filter(raw: str) -> str:
    """
    Validate -sev input. Accepts one layer name; everything MORE severe
    than it is included too ('high' -> CRITICAL + HIGH). Returns the
    canonical lowest layer or raises ValueError.
    """
    raw = raw.strip().upper()
    if raw not in SEVERITY_ORDER:
        raise ValueError(
            f"Invalid severity '{raw}'. Choose from: "
            f"{', '.join(SEVERITY_ORDER)}")
    return raw


def print_severity_legend() -> None:
    """Print the severity category table (for --sev-list)."""
    print("""
CORS severity layers (choose with -sev; chosen layer and worse are shown):

  CRITICAL  Arbitrary origin trusted WITH credentials - instant account theft
            bypasses: Reflected Origin, Null Origin
  HIGH      Origin suffix/prefix breaks, TLS downgrade, localhost regex
            bypasses: Bypass 1/2/18, Domain ends allow, Breaking TLS, localhost
  MEDIUM    Subdomain trust breaks + wildcard/regexp-combo breaks
            bypasses: Trusted Subdomains, Regexp bypass 1-21, combo bypasses
  LOW       Stage-1 regex break: origin REFLECTED but without credentials
            (no data theft yet, but origin filter is broken - stage 2 target)
            shown as: [REFLECTED][LOW]

Usage: -sev critical   show only CRITICAL hits
       -sev high       show CRITICAL + HIGH
       -sev medium     show CRITICAL + HIGH + MEDIUM (subdomain/regex breaks)
       -sev low        show everything incl. stage-1 regex breaks (default)
""")


# ============================================================================
# Target normalization
# ============================================================================

def normalize_target(raw_line: str) -> Optional[Target]:
    """
    Normalize an input line into a Target.

    Accepts bare domains (sub.example.com), full URLs
    (https://sub.example.com/path), and ignores blank lines / #comments.
    Returns None for invalid lines.
    """
    raw = raw_line.strip()
    if not raw or raw.startswith('#'):
        return None
    raw = unquote(raw, encoding='utf-8')

    parsed = urlparse(raw)
    if parsed.scheme in ('http', 'https') and parsed.netloc:
        return Target(
            raw=raw,
            host=parsed.netloc,
            provisional_url=raw,
            explicit_scheme=parsed.scheme,
        )

    # Bare domain: drop path/query/fragment leftovers and trailing dots
    host = raw.split('/')[0].split('?')[0].split('#')[0].strip().rstrip('.')
    if validators.domain(host):
        return Target(
            raw=raw,
            host=host,
            provisional_url=f'https://{host}',
            explicit_scheme=None,
        )
    return None


# ============================================================================
# CORS bypass payloads
# ============================================================================

class CORSBypassPayloads:
    """CORS bypass payload generation and management."""

    #: curated subset used by --fast for a first pass over huge lists
    FAST_NAMES = frozenset({
        'Reflected Origin', 'Breaking TLS', 'Trusted Subdomains',
        'Unencrypted Subdomains', 'Null Origin',
        'Unencrypted domain ends allow', 'Domain ends allow',
        'Localhost regex', 'Bypass 1', 'Bypass 2', 'Bypass 18',
        'Regexp bypass 1', 'Regexp bypass 9',
    })

    @staticmethod
    def generate(origin: str, malicious_domain: str) -> Dict[str, str]:
        """Generate CORS bypass payloads for an origin."""
        return {
            'Reflected Origin': f'https://{malicious_domain}',
            'Breaking TLS': f'http://{origin}',
            'Trusted Subdomains': f'https://subdomain.{origin}',
            'Unencrypted Subdomains': f'http://subdomain.{origin}',
            'Null Origin': 'null',
            'Unencrypted domain ends allow': f'http://attacker{origin}',
            'Domain ends allow': f'https://attacker{origin}',
            'Unencrypted localhost regex': f'http://localhost.{malicious_domain}',
            'Localhost regex': f'https://localhost.{malicious_domain}',
            'Bypass 1': f'http://{malicious_domain}.{origin}',
            'Bypass 2': f'https://{malicious_domain}.{origin}',
            'Bypass 3': f'https://{origin}._.{malicious_domain}',
            'Bypass 4': f'https://{origin}.-.{malicious_domain}',
            'Bypass 5': f'https://{origin}.,.{malicious_domain}',
            'Bypass 6': f'https://{origin}.;.{malicious_domain}',
            'Bypass 7': f'https://{origin}.!.{malicious_domain}',
            'Bypass 8': f"https://{origin}.' .{malicious_domain}",
            'Bypass 9': f'https://{origin}".{malicious_domain}',
            'Bypass 10': f'https://{origin}.({malicious_domain}',
            'Bypass 11': f'https://{origin}.){malicious_domain}',
            'Bypass 12': f'https://{origin}' + '.{' + f'{malicious_domain}',
            'Bypass 13': f'https://{origin}' + '.}' + f'{malicious_domain}',
            'Bypass 14': f'https://{origin}.*.{malicious_domain}',
            'Bypass 15': f'https://{origin}.&.{malicious_domain}',
            'Bypass 16': f'https://{origin}.`.{malicious_domain}',
            'Bypass 17': f'https://{origin}.+.{malicious_domain}',
            'Bypass 18': f'https://{origin}.{malicious_domain}',
            'Bypass 19': f'https://{origin}.=.{malicious_domain}',
            'Bypass 20': f'https://{origin}.~.{malicious_domain}',
            'Bypass 21': f'https://{origin}.$.{malicious_domain}',
            'Bypass 22': f'http://s{origin}',
            'Bypass 23': f'https://{origin.replace(".", "x")}',
            'Regexp bypass 1': f'{origin},.{malicious_domain}',
            'Regexp bypass 2': f'{origin}&.{malicious_domain}',
            'Regexp bypass 3': f"{origin}'.{malicious_domain}",
            'Regexp bypass 4': f'{origin}".{malicious_domain}',
            'Regexp bypass 5': f'{origin};.{malicious_domain}',
            'Regexp bypass 6': f'{origin}!.{malicious_domain}',
            'Regexp bypass 7': f'{origin}$.{malicious_domain}',
            'Regexp bypass 8': f'{origin}^.{malicious_domain}',
            'Regexp bypass 9': f'{origin}*.{malicious_domain}',
            'Regexp bypass 10': f'{origin}(.{malicious_domain}',
            'Regexp bypass 11': f'{origin}).{malicious_domain}',
            'Regexp bypass 12': f'{origin}+.{malicious_domain}',
            'Regexp bypass 13': f'{origin}=.{malicious_domain}',
            'Regexp bypass 14': f'{origin}`.{malicious_domain}',
            'Regexp bypass 15': f'{origin}~.{malicious_domain}',
            'Regexp bypass 16': f'{origin}-.{malicious_domain}',
            'Regexp bypass 17': f'{origin}_.{malicious_domain}',
            'Regexp bypass 18': f'{origin}|.{malicious_domain}',
            'Regexp bypass 19': f'https://{origin}' + '.{' + f'{malicious_domain}',
            'Regexp bypass 21': f'{origin}%.{malicious_domain}',
        }

    @classmethod
    def select(cls, origin: str, malicious_domain: str,
               fast_only: bool = False) -> Dict[str, str]:
        """Full payload set, or the curated --fast subset."""
        payloads = cls.generate(origin, malicious_domain)
        if fast_only:
            return {n: v for n, v in payloads.items() if n in cls.FAST_NAMES}
        return payloads


# ============================================================================
# Scanner
# ============================================================================

class CORSVulnerabilityScanner:
    """Async CORS scanner built for very large target lists."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = logger

        # Results / counters (single event-loop thread => no locks needed)
        self.results: List[ScanResult] = []
        self.vulnerable_results: List[ScanResult] = []
        self.error_count: int = 0
        self.tests_done: int = 0
        self.total_tests: int = 0
        self.alive_count: int = 0
        self.dead_count: int = 0
        self.invalid_count: int = 0
        self.http_status_codes: Dict[int, int] = {}
        self.vuln_by_target: Dict[str, int] = {}
        self.dead_samples: List[str] = []
        self.elapsed: float = 0.0

        # json/sarif need the full result set buffered; txt/jsonl stream out
        self._keep_all = config.output_format.lower() in ('json', 'sarif')
        self._out_fh = None
        self._started = 0.0
        self._last_progress_len = 0

    # ------------------------------------------------------------------ #
    # HTTP session
    # ------------------------------------------------------------------ #

    @asynccontextmanager
    async def _make_session(self):
        # aiodns (c-ares) cannot read system DNS on some Windows setups;
        # sanity-check it once and fall back to getaddrinfo if it is broken.
        resolver = None
        try:
            candidate = aiohttp.AsyncResolver()
            await candidate.resolve('example.com', 443)
            resolver = candidate
        except Exception:
            resolver = aiohttp.ThreadedResolver()

        connect_timeout = max(2.0, min(5.0, self.config.timeout / 2))
        connector = TCPConnector(
            ssl=False,                        # scanner never needs TLS validation
            use_dns_cache=True,
            ttl_dns_cache=600,
            limit=max(self.config.max_workers, 16),
            limit_per_host=max(1, self.config.per_host),
            enable_cleanup_closed=True,
            resolver=resolver,
        )
        timeout = ClientTimeout(
            total=self.config.timeout,
            connect=connect_timeout,
            sock_connect=connect_timeout,
        )
        default_headers = {
            "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                headers=default_headers,
                timeout=timeout,
            ) as session:
                yield session
        finally:
            with suppress(Exception):
                await resolver.close()


    def _proxy_url(self) -> Optional[str]:
        if not self.config.proxy:
            return None
        return self.config.proxy.get("https") or self.config.proxy.get("http")


    # ------------------------------------------------------------------ #
    # Core request
    # ------------------------------------------------------------------ #

    async def _test_bypass(self, session, url: str, bypass_name: str,
                           bypass_value: str) -> ScanResult:
        headers = {"Origin": bypass_value}
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)

        err: Optional[str] = None
        attempts = max(1, self.config.retries) + 1
        for attempt in range(1, attempts + 1):
            try:
                async with session.request(
                    self.config.method,
                    url,
                    headers=headers,
                    proxy=self._proxy_url(),
                    allow_redirects=False,
                ) as resp:
                    acac = resp.headers.get("Access-Control-Allow-Credentials")
                    acao = resp.headers.get("Access-Control-Allow-Origin")
                    self.http_status_codes[resp.status] = \
                        self.http_status_codes.get(resp.status, 0) + 1
                    # Stage-1: the server echoes our (malicious) origin back
                    # with or without credentials
                    reflected = (acao == bypass_value)
                    is_vuln = reflected and acac == "true"
                    return ScanResult(
                        url=url,
                        bypass_name=bypass_name,
                        bypass_value=bypass_value,
                        is_vulnerable=is_vuln,
                        response_code=resp.status,
                        acac=acac,
                        acao=acao,
                        severity=classify_severity(bypass_name, is_vuln,
                                                   reflected),
                        reflected=reflected,
                    )
            except asyncio.TimeoutError:
                err = "Timeout"
            except aiohttp.ClientConnectionError as exc:
                err = f"Connection error: {exc}"
            except aiohttp.ClientError as exc:
                err = str(exc) or type(exc).__name__
                break  # protocol-level problems are not worth retrying
            if attempt < attempts:
                await asyncio.sleep(self.config.backoff_factor * (2 ** (attempt - 1)))

        self.error_count += 1
        return ScanResult(
            url=url,
            bypass_name=bypass_name,
            bypass_value=bypass_value,
            is_vulnerable=False,
            error=err or "Unknown error",
        )

    # ------------------------------------------------------------------ #
    # Probe phase: fast dead-host elimination
    # ------------------------------------------------------------------ #

    async def _probe_one(self, session, sem, target: Target) -> Optional[str]:
        """Return a working URL for the target, or None if unreachable."""
        async with sem:
            if target.explicit_scheme:
                candidates = [target.provisional_url]
            elif self.config.scheme in ('https', 'http'):
                candidates = [f"{self.config.scheme}://{target.host}"]
            else:
                candidates = [f"https://{target.host}", f"http://{target.host}"]

            last_err = "unreachable"
            for url in candidates:
                try:
                    resp = await session.head(
                        url,
                        allow_redirects=True,
                        proxy=self._proxy_url(),
                        timeout=ClientTimeout(
                            total=min(self.config.timeout, 6), connect=3),
                    )
                    self.http_status_codes[resp.status] = \
                        self.http_status_codes.get(resp.status, 0) + 1
                    return url  # any HTTP answer == alive
                except asyncio.TimeoutError:
                    last_err = "probe timeout"
                except Exception as exc:  # noqa: BLE001 - DNS/connect weirdness
                    last_err = str(exc) or type(exc).__name__
            if len(self.dead_samples) < 25:
                self.dead_samples.append(f"{target.raw} ({last_err})")
            return None


    def scan(self, targets: List[Target]) -> Tuple[List[ScanResult], int]:
        _pick_event_loop_policy()
        return asyncio.run(self.run(targets))

    async def run(self, targets: List[Target]) -> Tuple[List[ScanResult], int]:
        self._started = time.monotonic()
        try:
            async with self._make_session() as session:
                if self.config.probe:
                    if not self.config.quiet:
                        self.logger.info("Probing targets (dead hosts skipped, https->http fallback)...")
                    urls = await self._probe_phase(session, targets)
                else:
                    urls = [t.provisional_url for t in targets]
                    self.alive_count = len(urls)

                if not urls:
                    self.logger.warning("No reachable targets to scan")
                    return self.results, len(self.vulnerable_results)

                payloads_per_target = len(CORSBypassPayloads.select(
                    'example.com', self.config.custom_domain, self.config.fast))
                self.total_tests = self.alive_count * payloads_per_target

                if not self.config.quiet:
                    self.logger.info(
                        f"Scanning {self.alive_count} target(s) | ~{self.total_tests} requests "
                        f"| workers={self.config.max_workers} | per-host={self.config.per_host}")

                progress = (None if self.config.quiet
                            else asyncio.create_task(self._progress_loop()))
                try:
                    if self.config.stop_on_first:
                        await self._scan_stop_on_first(session, urls)
                    else:
                        await self._scan_queue(session, urls)
                finally:
                    if progress is not None:
                        progress.cancel()
                        with suppress(asyncio.CancelledError):
                            await progress
                        sys.stderr.write("\n")
        finally:
            self.elapsed = time.monotonic() - self._started
            self._close_output()
        return self.results, len(self.vulnerable_results)

    async def _probe_phase(self, session, targets: List[Target]) -> List[str]:
        """Probe all targets in parallel; return alive URLs only."""
        sem = asyncio.Semaphore(max(1, self.config.max_workers))
        alive: List[str] = []
        total = len(targets)
        chunk = max(self.config.max_workers * 2, 256)
        for i in range(0, total, chunk):
            batch = [self._probe_one(session, sem, t) for t in targets[i:i + chunk]]
            for url in await asyncio.gather(*batch):
                if url is not None:
                    alive.append(url)
            if not self.config.quiet and total >= 500:
                sys.stderr.write(f"\r[PROBE] {min(i + chunk, total)}/{total} targets checked   ")
        if not self.config.quiet and total >= 500:
            sys.stderr.write("\n")
        self.alive_count = len(alive)
        self.dead_count = total - len(alive)
        if self.dead_count and not self.config.quiet:
            msg = f"{self.dead_count} unreachable target(s) skipped"
            if self.dead_samples and self.config.verbose:
                msg += f" | e.g. {self.dead_samples[0]}"
            self.logger.info(msg)
        return alive

    async def _scan_queue(self, session, urls: List[str]) -> None:
        """Producer/consumer: one global pool shared by every target."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=max(self.config.max_workers * 4, 256))
        producer = asyncio.create_task(self._produce(queue, urls))
        consumers = [asyncio.create_task(self._consume(session, queue))
                     for _ in range(max(1, self.config.max_workers))]
        await asyncio.gather(producer, *consumers)

    async def _produce(self, queue: asyncio.Queue, urls: List[str]) -> None:
        try:
            for url in urls:
                origin = urlparse(url).netloc
                payloads = CORSBypassPayloads.select(
                    origin, self.config.custom_domain, self.config.fast)
                for name, value in payloads.items():
                    await queue.put((url, name, value))
        finally:
            for _ in range(max(1, self.config.max_workers)):
                await queue.put(None)

    async def _consume(self, session, queue: asyncio.Queue) -> None:
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return
            url, name, value = item
            try:
                result = await self._test_bypass(session, url, name, value)
            finally:
                queue.task_done()
            self._handle_result(result)
            if self.config.rate_limit:
                await asyncio.sleep(self.config.rate_limit)

    async def _scan_stop_on_first(self, session, urls: List[str]) -> None:
        """Per-target early exit; targets still run in parallel."""
        sem = asyncio.Semaphore(max(1, self.config.max_workers))

        async def scan_one(url: str) -> None:
            origin = urlparse(url).netloc
            payloads = CORSBypassPayloads.select(
                origin, self.config.custom_domain, self.config.fast)
            for name, value in payloads.items():
                async with sem:
                    result = await self._test_bypass(session, url, name, value)
                self._handle_result(result)
                if result.is_vulnerable:
                    return

        chunk = max(self.config.max_workers * 2, 256)
        for i in range(0, len(urls), chunk):
            await asyncio.gather(*(scan_one(u) for u in urls[i:i + chunk]))


    # ------------------------------------------------------------------ #
    # Progress / result handling / streaming output
    # ------------------------------------------------------------------ #

    async def _progress_loop(self) -> None:
        interval = max(0.5, self.config.progress_interval)
        while True:
            await asyncio.sleep(interval)
            self._progress_write()

    def _progress_write(self) -> None:
        elapsed = max(time.monotonic() - self._started, 1e-6)
        rate = self.tests_done / elapsed
        remaining = max(0, self.total_tests - self.tests_done)
        eta = remaining / rate if rate > 0 else 0.0
        line = (
            f"\r[SCAN] {self.tests_done}/{self.total_tests} tests | "
            f"vuln: {len(self.vulnerable_results)} | err: {self.error_count} | "
            f"{rate:,.0f} req/s | ETA {int(eta // 60):02d}:{int(eta % 60):02d}"
        )
        pad = max(0, self._last_progress_len - len(line))
        sys.stderr.write(line + " " * pad)
        self._last_progress_len = len(line) + pad

    def _severity_color(self, sev: str):
        """Colorama color for a severity layer."""
        return {
            'CRITICAL': Fore.RED + Style.BRIGHT,
            'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.CYAN,
        }.get(sev, Fore.RED)

    def _passes_severity(self, result: ScanResult) -> bool:
        """Severity-layer filter: result must be at least as severe as chosen."""
        if not result.severity:
            return True  # plain SAFE/ERROR rows are governed by other flags
        return severity_rank(result.severity) <= \
            severity_rank(self.config.severity_filter)

    def _handle_result(self, result: ScanResult) -> None:
        self.tests_done += 1
        if result.is_vulnerable:
            self.vulnerable_results.append(result)
            self.vuln_by_target[result.url] = \
                self.vuln_by_target.get(result.url, 0) + 1
        elif result.error and self.config.verbose:
            self.logger.debug(f"{result.url} {result.bypass_name}: {result.error}")

        if result.is_vulnerable or result.reflected or self._keep_all:
            self.results.append(result)

        if result.is_vulnerable or result.reflected or self.config.show_safe:
            if self._passes_severity(result):
                self._print_result(result)

        self._stream_write(result)

    def _print_result(self, result: ScanResult) -> None:
        if self.config.vulnerable_only and not result.is_vulnerable:
            return
        if result.is_vulnerable:
            status = f"[VULNERABLE][{result.severity}]"
        elif result.reflected:
            status = "[REFLECTED][LOW]"
        elif result.error:
            status = "[ERROR]"
        else:
            status = "[SAFE]"
        output = f"{status} {result.url} | {result.bypass_name}: {result.bypass_value}"
        if self.config.no_color:
            print(output)
        else:
            color = (self._severity_color(result.severity) if result.is_vulnerable
                     else (Fore.CYAN if result.reflected
                           else (Fore.YELLOW if result.error else Fore.RED)))
            print(f"{color}{output}{Style.RESET_ALL}")

    def _final_path(self) -> Path:
        path = Path(self.config.output_file)
        suffix = '.jsonl' if self.config.output_format.lower() == 'jsonl' else '.txt'
        return path if path.suffix == suffix else path.with_suffix(suffix)

    def _stream_write(self, result: ScanResult) -> None:
        fmt = self.config.output_format.lower()
        if not self.config.output_file or fmt not in ('txt', 'jsonl'):
            return
        if self.config.vulnerable_only and not result.is_vulnerable:
            return
        if result.is_vulnerable or result.reflected:
            if not self._passes_severity(result):
                return
        if self._out_fh is None:
            self._out_fh = open(self._final_path(), 'w', encoding='utf-8',
                                buffering=8192)
        if fmt == 'jsonl':
            self._out_fh.write(json.dumps(result.to_dict()) + '\n')
        else:
            self._out_fh.write(str(result) + '\n')

    def _close_output(self) -> None:
        if self._out_fh is not None:
            try:
                self._out_fh.close()
            except OSError:
                pass
            self._out_fh = None
        elif self.config.output_file and \
                self.config.output_format.lower() in ('txt', 'jsonl'):
            try:
                self._final_path().touch()  # guarantee the file exists
            except OSError:
                pass


    def _generate_sarif_report(self) -> Dict:
        sarif_results = []
        for result in self.results:
            if self.config.vulnerable_only and not result.is_vulnerable:
                continue
            level = "warning" if result.is_vulnerable else "note"
            verdict = ("CORS misconfiguration detected"
                       if result.is_vulnerable else "No CORS misconfiguration found")
            entry = {
                "ruleId": "cors-bypass",
                "level": level,
                "message": {"text": f"{verdict} via {result.bypass_name}"},
                "locations": [{"physicalLocation":
                               {"address": {"uri": result.url}}}],
                "properties": {
                    "bypass_name": result.bypass_name,
                    "bypass_value": result.bypass_value,
                    "response_code": result.response_code,
                    "access_control_allow_credentials": result.acac,
                    "access_control_allow_origin": result.acao,
                    "vulnerability_type": "CORS",
                    "timestamp": str(result.timestamp),
                },
            }
            if result.error:
                entry["properties"]["error"] = result.error
            sarif_results.append(entry)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                       "master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CorsOne",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/omranisecurity/CorsOne",
                        "rules": [{
                            "id": "cors-bypass",
                            "name": "CORS Misconfiguration",
                            "shortDescription": {
                                "text": "Detection of CORS misconfigurations"},
                            "fullDescription": {
                                "text": "Tests for CORS misconfigurations that "
                                        "could allow unauthorized cross-origin "
                                        "requests with credentials"},
                            "defaultConfiguration": {"level": "warning"},
                            "properties": {
                                "category": "Security",
                                "tags": ["cors", "security", "misconfiguration"]},
                        }],
                    }
                },
                "results": sarif_results,
            }],
        }

    def save_results(self) -> None:
        """Persist results: txt/jsonl were streamed live; json/sarif written here."""
        if not self.config.output_file:
            return
        fmt = self.config.output_format.lower()

        if fmt in ('txt', 'jsonl'):
            self.logger.info(f"Results saved to {self._final_path()}")
            return

        if fmt not in ('json', 'sarif'):
            self.logger.error(f"Unsupported format: {fmt}. Use txt, jsonl, json, or sarif.")
            return

        try:
            if fmt == 'sarif':
                data: Any = self._generate_sarif_report()
            else:
                data = [r.to_dict() for r in self.results
                        if not self.config.vulnerable_only or r.is_vulnerable]
            final = Path(self.config.output_file).with_suffix('.json')
            with open(final, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            self.logger.info(f"Results saved to {final}")
        except OSError as e:
            self.logger.error(f"Failed to save results: {e}")

    def print_summary(self) -> None:
        """Print scan summary."""
        def colorize(text: str, color) -> str:
            if self.config.no_color:
                return text
            return f"{color}{text}{Style.RESET_ALL}"

        total = self.tests_done
        vulnerable = len(self.vulnerable_results)
        stage1 = sum(1 for r in self.results
                     if r.reflected and not r.is_vulnerable)
        safe = max(0, total - vulnerable - stage1 - self.error_count)
        elapsed = max(self.elapsed, 1e-6)
        rate = total / elapsed

        # Count findings per severity layer
        sev_counts: Dict[str, int] = {}
        for r in self.results:
            if r.is_vulnerable and r.severity:
                sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1

        print(f"\n{'='*70}")
        print(f"{'SCAN SUMMARY':^70}")
        print(f"{'='*70}")
        print(f"Targets alive:        {self.alive_count}")
        print(f"Targets unreachable:  {colorize(str(self.dead_count), Fore.YELLOW)}")
        print(f"Targets invalid:      {colorize(str(self.invalid_count), Fore.YELLOW)}")
        print(f"Total tests:          {total}")
        print(f"Vulnerable:           {colorize(str(vulnerable), Fore.GREEN)}")
        print(f"Stage-1 reflected:    {colorize(str(stage1), Fore.CYAN)}"
              f"  (origin reflected, no creds - LOW)")
        print(f"Safe:                 {colorize(str(safe), Fore.RED)}")
        print(f"Errors:               {colorize(str(self.error_count), Fore.YELLOW)}")
        print(f"Elapsed:              {elapsed:.1f}s ({rate:,.0f} req/s)")

        if sev_counts:
            print(f"\n{colorize('Findings by severity:', Fore.CYAN)}")
            for sev in SEVERITY_ORDER:
                if sev in sev_counts:
                    c = sev_counts[sev]
                    if self.config.no_color:
                        print(f"  - {sev:<8} {c}")
                    else:
                        print(f"  - {self._severity_color(sev)}{sev:<8}{Style.RESET_ALL} {c}")
            print(f"\n  (filter with: -sev <layer> | see all: --sev-list)")

        if self.http_status_codes:
            print(f"\n{colorize('HTTP Status Codes:', Fore.CYAN)}")
            for status_code in sorted(self.http_status_codes):
                print(f"  - {status_code}: {self.http_status_codes[status_code]}")

        if vulnerable > 0:
            print(f"\n{colorize('Vulnerable targets:', Fore.GREEN)}")
            for idx, (url, hits) in enumerate(self.vuln_by_target.items()):
                if idx >= 25:
                    print(f"  - ...and {len(self.vuln_by_target) - idx} more")
                    break
                worst = min(
                    (r.severity or 'MEDIUM'
                     for r in self.vulnerable_results if r.url == url),
                    key=severity_rank)
                tag = ("" if self.config.no_color
                       else f"{self._severity_color(worst)}[{worst}]{Style.RESET_ALL} ")
                note = ""
                if hits >= 25:
                    note = colorize("  <- reflects almost every origin (verify manually)",
                                    Fore.MAGENTA)
                print(f"  - {tag}{url} ({hits} bypass hit(s)){note}")

        print(f"{'='*70}\n")


class DomainValidator:
    """Validates that custom domain is a base domain without protocol/subdomain."""

    @staticmethod
    def validate(domain: str) -> str:
        domain = domain.strip()

        if domain.startswith('http://') or domain.startswith('https://'):
            raise ValueError(
                "Custom domain should not include 'http://' or 'https://' protocol")

        parts = domain.split('.')
        if len(parts) < 2:
            raise ValueError("Custom domain must be a valid domain (e.g., example.com)")

        if validators.domain(domain):
            return domain
        raise ValueError(f"Invalid domain format: {domain}")


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser."""
    parser = argparse.ArgumentParser(
        prog='CorsOne',
        description='CORS Misconfiguration Discovery Tool (insane-speed rewrite)',
        epilog='Version: 2.0.0 | Based on CorsOne by omranisecurity (MIT)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-u', '--url', help='Target URL to scan')
    input_group.add_argument('-l', '--list',
                             help='File with targets, one per line (bare domains are fine)')

    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET',
                        help='HTTP method (default: GET)')
    parser.add_argument('-sof', '--stop-on-first', action='store_true',
                        help='Stop testing a target after its first vulnerability')
    parser.add_argument('-cd', '--custom-domain', default='attacker.com',
                        help='Custom domain for payloads (default: attacker.com)')
    parser.add_argument('-H', '--headers',
                        help='Custom headers as JSON (e.g., \'{"Cookie": "session=abc123"}\')')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., socks5://host:port)')

    perf = parser.add_argument_group('speed')
    perf.add_argument('-w', '--workers', type=int, default=200,
                      help='Global concurrent requests (default: 200)')
    perf.add_argument('--per-host', type=int, default=25,
                      help='Max concurrent requests per host (default: 25)')
    perf.add_argument('--fast', action='store_true',
                      help='Test only a curated payload subset (fast first pass)')
    perf.add_argument('--probe', action=argparse.BooleanOptionalAction, default=True,
                      help='Probe hosts first, skip dead ones (default: on)')
    perf.add_argument('--scheme', choices=['auto', 'https', 'http'], default='auto',
                      help='Scheme for bare domains (default: auto = https, then http)')
    perf.add_argument('-rl', '--rate-limit', type=float, default=0,
                      help='Delay between requests in seconds (default: 0)')
    perf.add_argument('-t', '--timeout', type=int, default=8,
                      help='Request timeout in seconds (default: 8)')
    perf.add_argument('-r', '--retries', type=int, default=1,
                      help='Retries for connection-level failures (default: 1)')

    out = parser.add_argument_group('output')
    out.add_argument('-o', '--output', help='Output file for results')
    out.add_argument('-f', '--format', choices=['txt', 'jsonl', 'json', 'sarif'],
                     default='txt', help='Output format (default: txt; txt/jsonl stream live)')
    out.add_argument('--show-safe', action='store_true',
                     help='Print every test result live, not just vulnerabilities')
    out.add_argument('--sev', default='LOW',
                     choices=[n.lower() for n in SEVERITY_ORDER],
                     help='Lowest severity layer to show incl. everything more '
                          'severe (default: low; everything is shown)')
    out.add_argument('--sev-list', action='store_true',
                     help='Print the severity category table and exit')
    out.add_argument('-vo', '--vuln-only', action='store_true',
                     help='Show and save only vulnerable results')
    out.add_argument('-q', '--quiet', action='store_true',
                     help='No banner, no progress line - vulnerable hits only')
    out.add_argument('--log', help='Log file path (only created if specified)')
    out.add_argument('-nc', '--no-color', action='store_true', help='Disable colored output')
    out.add_argument('-s', '--silent', action='store_true', help='Silent mode (no banner)')
    out.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')

    parser.add_argument('--version', action='store_true', help='Show version')
    return parser


def print_banner() -> None:
    """Print tool banner."""
    print("""
    +------------------------------------------------------------+
    |                                                            |
    |                          CorsOne                           |
    |        CORS Misconfiguration Discovery Tool v2.0           |
    |                                                            |
    |          Insanely Fast | Streaming | Reliable              |
    |                                                            |
    |        https://github.com/omranisecurity/CorsOne           |
    |                                                            |
    +------------------------------------------------------------+
    """)


def main() -> None:
    """Main entry point."""
    parser = create_argument_parser()
    args = parser.parse_args()

    if args.version:
        print("CorsOne v2.0.0")
        sys.exit(0)

    if args.sev_list:
        print_severity_legend()
        sys.exit(0)

    try:
        severity_low = parse_severity_filter(args.sev)
    except ValueError as e:
        parser.error(str(e))

    _setup_logging(verbose=args.verbose, log_file=args.log)

    if not args.silent and not args.quiet:
        print_banner()

    # ---- Collect raw target lines -------------------------------------
    raw_lines: List[str] = []
    if args.url:
        raw_lines = [args.url]
    elif args.list:
        try:
            with open(args.list, 'r', encoding='utf-8', errors='ignore') as f:
                raw_lines = f.read().splitlines()
        except OSError as e:
            logger.error(f"Failed to read target list: {e}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        raw_lines = sys.stdin.read().splitlines()
    else:
        parser.print_help()
        sys.exit(1)

    # ---- Normalize + dedupe -------------------------------------------
    targets: List[Target] = []
    seen = set()
    invalid = 0
    for line in raw_lines:
        target = normalize_target(line)
        if target is None:
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                invalid += 1
            continue
        key = (target.host, target.explicit_scheme or '',
               target.provisional_url.lower())
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)

    if not targets:
        logger.error("No valid targets to scan")
        sys.exit(1)
    logger.info(
        f"Loaded {len(targets)} unique target(s)"
        + (f", {invalid} invalid line(s) skipped" if invalid else ""))

    # ---- Other options -------------------------------------------------
    try:
        custom_domain = DomainValidator.validate(args.custom_domain)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    custom_headers: Optional[Dict[str, str]] = None
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except json.JSONDecodeError:
            logger.error('Invalid JSON for headers. Use: {"Header-Name": "value"}')
            sys.exit(1)

    proxy = {'http': args.proxy, 'https': args.proxy} if args.proxy else None

    config = ScanConfig(
        url=targets[0].provisional_url,
        method=args.method,
        custom_domain=custom_domain,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        retries=args.retries,
        max_workers=args.workers,
        per_host=args.per_host,
        stop_on_first=args.stop_on_first,
        no_color=args.no_color,
        output_file=args.output,
        output_format=args.format,
        output_log=args.log,
        custom_headers=custom_headers,
        proxy=proxy,
        verbose=args.verbose,
        vulnerable_only=args.vuln_only,
        probe=args.probe,
        scheme=args.scheme,
        show_safe=args.show_safe,
        quiet=args.quiet,
        fast=args.fast,
        severity_filter=severity_low,
    )

    scanner = CORSVulnerabilityScanner(config)
    scanner.invalid_count = invalid

    try:
        scanner.scan(targets)
        scanner.save_results()
        if not args.silent and not args.quiet:
            scanner.print_summary()
    except KeyboardInterrupt:
        logger.warning("Interrupted - saving partial results...")
        scanner.save_results()
        sys.exit(130)


if __name__ == '__main__':
    main()

