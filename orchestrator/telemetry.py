"""
Sentinel observability — OTel tracing, metrics, and token cost reporting.

Tracing:
  Exports to OTLP when OTEL_EXPORTER_OTLP_ENDPOINT is set, console otherwise.
  Spans: sentinel.remediation → sentinel.scan / sentinel.patch / sentinel.verify / sentinel.pr_create
  Each LLM call gets its own sentinel.llm_call child span.

Metrics:
  remediation_duration_seconds  histogram  full pipeline wall time
  scan_duration_seconds         histogram  OSV scan wall time
  verify_duration_seconds       histogram  sandbox build wall time
  cves_found_total              counter    CVEs detected per run
  patch_attempts_total          counter    patch+verify cycles
  pr_opened_total               counter    PRs successfully opened
  llm_tokens_total              counter    tokens by model/type/stage
  llm_cost_usd_total            counter    $ cost by model/stage

Token cost report:
  Printed at the end of every run. Shows per-stage token usage,
  cache savings, and total cost for the repo.
"""

import os
import time
import contextvars
from dataclasses import dataclass, field
from typing import Optional

from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader

# ── Cost table (USD per million tokens) ──────────────────────────────────────
# (input, output, cache_write, cache_read)
_COST_PER_MTOK: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-4-8":           (15.00, 75.00, 18.75, 1.875),
    "claude-opus-4-6":           (15.00, 75.00, 18.75, 1.875),
    "claude-sonnet-4-6":         (3.00,  15.00, 3.75,  0.30),
    "claude-haiku-4-5-20251001": (0.80,  4.00,  1.00,  0.08),
    "claude-haiku-4-5":          (0.80,  4.00,  1.00,  0.08),
    "gemini-2.5-flash":          (0.15,  0.60,  0.0,   0.0),
    "gemini-2.5-pro":            (1.25,  10.00, 0.0,   0.0),
    "gemini-2.0-flash":          (0.10,  0.40,  0.0,   0.0),
}
_DEFAULT_COST = (3.00, 15.00, 0.0, 0.0)  # fallback — assume Sonnet-class


def cost_usd(model: str, input_tok: int, output_tok: int,
             cache_write_tok: int = 0, cache_read_tok: int = 0) -> float:
    rates = _COST_PER_MTOK.get(model, _DEFAULT_COST)
    return (
        input_tok       * rates[0] / 1_000_000 +
        output_tok      * rates[1] / 1_000_000 +
        cache_write_tok * rates[2] / 1_000_000 +
        cache_read_tok  * rates[3] / 1_000_000
    )


def cache_savings_usd(model: str, cache_read_tok: int) -> float:
    """Dollar value of tokens served from cache vs. billed at full input price."""
    rates = _COST_PER_MTOK.get(model, _DEFAULT_COST)
    full_price = cache_read_tok * rates[0] / 1_000_000
    cache_price = cache_read_tok * rates[3] / 1_000_000
    return max(0.0, full_price - cache_price)


# ── Per-call record ───────────────────────────────────────────────────────────

@dataclass
class _CallRecord:
    stage: str
    model: str
    input_tok: int = 0
    output_tok: int = 0
    cache_write_tok: int = 0
    cache_read_tok: int = 0

    @property
    def cost(self) -> float:
        return cost_usd(self.model, self.input_tok, self.output_tok,
                        self.cache_write_tok, self.cache_read_tok)

    @property
    def savings(self) -> float:
        return cache_savings_usd(self.model, self.cache_read_tok)


# ── Per-run token tracker ─────────────────────────────────────────────────────

class TokenUsageTracker:
    """
    Accumulates token usage across all LLM calls in one remediation run.
    Call .record() from llm_client after each API response.
    Call .print_report() at the end of the run.
    """

    def __init__(self, repo_url: str):
        self.repo = repo_url
        self._calls: list[_CallRecord] = []

    def record(self, stage: str, model: str, input_tok: int, output_tok: int,
               cache_write_tok: int = 0, cache_read_tok: int = 0):
        self._calls.append(_CallRecord(
            stage=stage, model=model,
            input_tok=input_tok, output_tok=output_tok,
            cache_write_tok=cache_write_tok, cache_read_tok=cache_read_tok,
        ))

    def total_cost(self) -> float:
        return sum(c.cost for c in self._calls)

    def total_savings(self) -> float:
        return sum(c.savings for c in self._calls)

    def print_report(self):
        if not self._calls:
            return

        # Group by stage
        stages: dict[str, list[_CallRecord]] = {}
        for c in self._calls:
            stages.setdefault(c.stage, []).append(c)

        w = 76
        print("\n" + "═" * w)
        print(f"  Sentinel Token & Cost Report")
        print(f"  Repo: {self.repo}")
        print("═" * w)
        print(f"  {'Stage':<22} {'Model':<28} {'In':>7} {'Out':>6} {'Cache↓':>8} {'Cache↑':>8} {'Cost':>8}")
        print("  " + "─" * (w - 2))

        for stage, calls in stages.items():
            for c in calls:
                cache_r = f"{c.cache_read_tok:,}" if c.cache_read_tok else "—"
                cache_w = f"{c.cache_write_tok:,}" if c.cache_write_tok else "—"
                print(f"  {stage:<22} {c.model:<28} {c.input_tok:>7,} {c.output_tok:>6,} "
                      f"{cache_r:>8} {cache_w:>8} ${c.cost:>7.4f}")
                if c.savings > 0:
                    print(f"  {'':22} {'cache saved:':>28} {'':>7} {'':>6} {'':>8} {'':>8} "
                          f"\033[32m-${c.savings:>6.4f}\033[0m")

        total_in  = sum(c.input_tok for c in self._calls)
        total_out = sum(c.output_tok for c in self._calls)
        total_cr  = sum(c.cache_read_tok for c in self._calls)
        total_cw  = sum(c.cache_write_tok for c in self._calls)
        total_cost = self.total_cost()
        total_saved = self.total_savings()

        print("  " + "─" * (w - 2))
        cr_str = f"{total_cr:,}" if total_cr else "—"
        cw_str = f"{total_cw:,}" if total_cw else "—"
        print(f"  {'TOTAL':<22} {'':<28} {total_in:>7,} {total_out:>6,} "
              f"{cr_str:>8} {cw_str:>8} ${total_cost:>7.4f}")
        if total_saved > 0:
            print(f"  {'Cache savings':.<51}\033[32m -${total_saved:.4f}\033[0m")
            print(f"  {'Net cost (after savings)':.<51}\033[1m  ${total_cost:.4f}\033[0m")
        print("═" * w + "\n")


# ── Context var — one tracker per remediation run ────────────────────────────

_tracker_var: contextvars.ContextVar[Optional[TokenUsageTracker]] = \
    contextvars.ContextVar("sentinel_tracker", default=None)


def set_tracker(tracker: TokenUsageTracker):
    _tracker_var.set(tracker)


def get_tracker() -> Optional[TokenUsageTracker]:
    return _tracker_var.get()


# ── OTel setup ────────────────────────────────────────────────────────────────

_tracer: Optional[trace.Tracer] = None
_meter: Optional[metrics.Meter] = None

# Pipeline-level metrics (populated after setup_telemetry())
remediation_duration:  Optional[metrics.Histogram] = None
scan_duration:         Optional[metrics.Histogram] = None
verify_duration:       Optional[metrics.Histogram] = None
cves_found_counter:    Optional[metrics.Counter] = None
patch_attempts_counter: Optional[metrics.Counter] = None
pr_opened_counter:     Optional[metrics.Counter] = None
llm_tokens_counter:    Optional[metrics.Counter] = None
llm_cost_counter:      Optional[metrics.Counter] = None


def setup_telemetry(service_name: str = "sentinel"):
    global _tracer, _meter
    global remediation_duration, scan_duration, verify_duration
    global cves_found_counter, patch_attempts_counter, pr_opened_counter
    global llm_tokens_counter, llm_cost_counter

    # ── Tracer ────────────────────────────────────────────────────────────────
    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

    tp = TracerProvider()
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{otlp_endpoint}/v1/traces")))
        print(f"  [OTel] Exporting traces → {otlp_endpoint}")
    else:
        tp.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(tp)
    _tracer = trace.get_tracer(service_name)

    # ── Meter ─────────────────────────────────────────────────────────────────
    if otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=f"{otlp_endpoint}/v1/metrics"))
    else:
        reader = PeriodicExportingMetricReader(ConsoleMetricExporter(), export_interval_millis=60_000)

    mp = MeterProvider(metric_readers=[reader])
    metrics.set_meter_provider(mp)
    _meter = metrics.get_meter(service_name)

    # ── Instruments ───────────────────────────────────────────────────────────
    remediation_duration  = _meter.create_histogram("sentinel.remediation_duration_seconds", unit="s")
    scan_duration         = _meter.create_histogram("sentinel.scan_duration_seconds", unit="s")
    verify_duration       = _meter.create_histogram("sentinel.verify_duration_seconds", unit="s")
    cves_found_counter    = _meter.create_counter("sentinel.cves_found_total")
    patch_attempts_counter = _meter.create_counter("sentinel.patch_attempts_total")
    pr_opened_counter     = _meter.create_counter("sentinel.pr_opened_total")
    llm_tokens_counter    = _meter.create_counter("sentinel.llm_tokens_total")
    llm_cost_counter      = _meter.create_counter("sentinel.llm_cost_usd_total", unit="USD")


def get_tracer() -> trace.Tracer:
    global _tracer
    if _tracer is None:
        setup_telemetry()
    return _tracer


def record_llm_tokens(stage: str, model: str, input_tok: int, output_tok: int,
                      cache_write_tok: int = 0, cache_read_tok: int = 0,
                      repo: str = ""):
    """Record token usage to OTel metrics + the per-run cost tracker."""
    # Per-run cost tracker
    tracker = get_tracker()
    if tracker:
        tracker.record(stage, model, input_tok, output_tok, cache_write_tok, cache_read_tok)

    # OTel counters
    if llm_tokens_counter:
        attrs = {"model": model, "stage": stage, "repo": repo}
        llm_tokens_counter.add(input_tok,       {**attrs, "type": "input"})
        llm_tokens_counter.add(output_tok,       {**attrs, "type": "output"})
        if cache_write_tok:
            llm_tokens_counter.add(cache_write_tok, {**attrs, "type": "cache_write"})
        if cache_read_tok:
            llm_tokens_counter.add(cache_read_tok,  {**attrs, "type": "cache_read"})

    if llm_cost_counter:
        total = cost_usd(model, input_tok, output_tok, cache_write_tok, cache_read_tok)
        llm_cost_counter.add(total, {"model": model, "stage": stage, "repo": repo})
