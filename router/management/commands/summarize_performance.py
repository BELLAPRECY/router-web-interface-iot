import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError


def metric_summary(values):
    values = sorted(float(value) for value in values)
    if not values:
        return None
    p95_index = max(0, math.ceil(0.95 * len(values)) - 1)
    return {
        "count": len(values),
        "min": round(values[0], 3),
        "mean": round(statistics.fmean(values), 3),
        "median": round(statistics.median(values), 3),
        "p95": round(values[p95_index], 3),
        "max": round(values[-1], 3),
    }


def load_events(paths):
    events = []
    for path in paths:
        source = Path(path)
        if not source.is_file():
            raise CommandError(f"Log file does not exist: {source}")
        with source.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as error:
                    raise CommandError(
                        f"Invalid JSON in {source} at line {line_number}: {error}"
                    ) from error
    return events


def build_summary(events):
    http_groups = defaultdict(list)
    router_groups = defaultdict(list)

    for event in events:
        condition = event.get("condition", "unknown")
        if event.get("event") == "http_request":
            key = (
                condition,
                event.get("path", "unknown"),
                event.get("outcome", "unknown"),
            )
            http_groups[key].append(event)
        elif event.get("event") == "router_call":
            key = (condition, event.get("operation", "unknown"))
            router_groups[key].append(event)
    http = []
    for (condition, path, outcome), group in sorted(http_groups.items()):
        durations = [item["duration_ms"] for item in group if "duration_ms" in item]
        cpu = [item["cpu_ms"] for item in group if "cpu_ms" in item]
        rss = [item["rss_end_mb"] for item in group if "rss_end_mb" in item]
        rss_delta = [
            item["rss_delta_mb"] for item in group if "rss_delta_mb" in item
        ]
        http.append(
            {
                "condition": condition,
                "path": path,
                "outcome": outcome,
                "errors": sum(item.get("status", 0) >= 400 for item in group),
                "latency_ms": metric_summary(durations),
                "cpu_ms": metric_summary(cpu),
                "rss_mb": metric_summary(rss),
                "rss_delta_mb": metric_summary(rss_delta),
            }
        )

    router_calls = []
    for (condition, operation), group in sorted(router_groups.items()):
        durations = [item["duration_ms"] for item in group if "duration_ms" in item]
        router_calls.append(
            {
                "condition": condition,
                "operation": operation,
                "failures": sum(item.get("successful") is False for item in group),
                "latency_ms": metric_summary(durations),
            }
        )

    allowed_by_path = defaultdict(lambda: defaultdict(list))
    for event in events:
        if (
            event.get("event") == "http_request"
            and event.get("outcome") == "allowed"
            and event.get("status", 500) < 400
            and "duration_ms" in event
        ):
            allowed_by_path[event.get("path", "unknown")][event.get("condition")].append(
                event["duration_ms"]
            )

    comparisons = []
    for path, conditions in sorted(allowed_by_path.items()):
        if conditions.get("C0") and conditions.get("C1"):
            c0_mean = statistics.fmean(conditions["C0"])
            c1_mean = statistics.fmean(conditions["C1"])
            overhead = c1_mean - c0_mean
            comparisons.append(
                {
                    "path": path,
                    "c0_count": len(conditions["C0"]),
                    "c1_count": len(conditions["C1"]),
                    "c0_mean_ms": round(c0_mean, 3),
                    "c1_mean_ms": round(c1_mean, 3),
                    "overhead_ms": round(overhead, 3),
                    "relative_overhead_percent": (
                        round(overhead / c0_mean * 100, 3) if c0_mean else None
                    ),
                }
            )

    return {
        "run_ids": sorted({event.get("run_id") for event in events if event.get("run_id")}),
        "event_count": len(events),
        "http": http,
        "router_calls": router_calls,
        "allowed_request_comparisons": comparisons,
    }


class Command(BaseCommand):
    help = "Summarize structured performance JSONL logs."

    def add_arguments(self, parser):
        parser.add_argument("log_files", nargs="+")
        parser.add_argument(
            "--json-output",
            help="Optionally write the complete machine-readable summary to this file.",
        )

    def handle(self, *args, **options):
        summary = build_summary(load_events(options["log_files"]))
        if not summary["event_count"]:
            raise CommandError("The supplied logs contain no events.")

        self.stdout.write(f"Runs: {', '.join(summary['run_ids']) or 'unknown'}")
        self.stdout.write(f"Events: {summary['event_count']}")
        self.stdout.write("\nHTTP request latency")
        self.stdout.write(
            "condition path outcome count mean_ms p95_ms max_ms mean_cpu_ms "
            "mean_rss_mb peak_rss_mb errors"
        )
        for row in summary["http"]:
            latency = row["latency_ms"]
            cpu = row["cpu_ms"]
            rss = row["rss_mb"]
            mean_rss = f"{rss['mean']:.3f}" if rss else "n/a"
            peak_rss = f"{rss['max']:.3f}" if rss else "n/a"
            self.stdout.write(
                f"{row['condition']} {row['path']} {row['outcome']} "
                f"{latency['count']} {latency['mean']:.3f} "
                f"{latency['p95']:.3f} {latency['max']:.3f} "
                f"{cpu['mean']:.3f} {mean_rss} {peak_rss} {row['errors']}"
            )

        if summary["router_calls"]:
            self.stdout.write("\nOpenWrt call latency")
            self.stdout.write("condition operation count mean_ms p95_ms failures")
            for row in summary["router_calls"]:
                latency = row["latency_ms"]
                self.stdout.write(
                    f"{row['condition']} {row['operation']} {latency['count']} "
                    f"{latency['mean']:.3f} {latency['p95']:.3f} {row['failures']}"
                )

        if summary["allowed_request_comparisons"]:
            self.stdout.write("\nValid-request C1 overhead versus C0")
            self.stdout.write("path c0_n c1_n c0_mean_ms c1_mean_ms overhead_ms overhead_pct")
            for row in summary["allowed_request_comparisons"]:
                relative = row["relative_overhead_percent"]
                relative_text = f"{relative:.3f}" if relative is not None else "n/a"
                self.stdout.write(
                    f"{row['path']} {row['c0_count']} {row['c1_count']} "
                    f"{row['c0_mean_ms']:.3f} {row['c1_mean_ms']:.3f} "
                    f"{row['overhead_ms']:.3f} {relative_text}"
                )

        if options["json_output"]:
            destination = Path(options["json_output"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            self.stdout.write(self.style.SUCCESS(f"Wrote JSON summary to {destination}"))
