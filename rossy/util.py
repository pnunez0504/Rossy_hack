"""Shared UI/logging helpers. Falls back to plain print if `rich` is missing."""
from __future__ import annotations
import sys, time

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    _console = Console()
    HAVE_RICH = True
except Exception:  # pragma: no cover - rich optional
    _console = None
    HAVE_RICH = False

BANNER = r"""
  ____                        _____            _       _ _
 |  _ \ ___  ___ ___ _   _   | ____|_  ___ __ | | ___ (_) |_
 | |_) / _ \/ __/ __| | | |  |  _| \ \/ / '_ \| |/ _ \| | __|
 |  _ < (_) \__ \__ \ |_| |  | |___ >  <| |_) | | (_) | | |_
 |_| \_\___/|___/___/\__, |  |_____/_/\_\ .__/|_|\___/|_|\__|
                      |___/             |_|   ROS2 / ESP32-S3 rover kit
"""

_COLORS = {"info": "cyan", "ok": "green", "warn": "yellow", "err": "red", "hit": "bold magenta"}
_TAGS = {"info": "*", "ok": "+", "warn": "!", "err": "x", "hit": ">>"}


def _ts() -> str:
    return time.strftime("%H:%M:%S")


def log(level: str, msg: str) -> None:
    tag = _TAGS.get(level, "*")
    if HAVE_RICH:
        color = _COLORS.get(level, "white")
        _console.print(f"[dim]{_ts()}[/dim] [{color}][{tag}][/{color}] {msg}")
    else:
        print(f"{_ts()} [{tag}] {msg}")


def info(m): log("info", m)
def ok(m): log("ok", m)
def warn(m): log("warn", m)
def err(m): log("err", m)
def hit(m): log("hit", m)


def banner() -> None:
    if HAVE_RICH:
        _console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    else:
        print(BANNER)


def rule(title: str = "") -> None:
    if HAVE_RICH:
        _console.rule(f"[bold]{title}[/bold]" if title else "")
    else:
        print("\n" + "=" * 8 + f" {title} " + "=" * 8)


def table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    if HAVE_RICH and rows:
        t = Table(title=title, header_style="bold cyan", show_lines=False)
        for c in columns:
            t.add_column(c, overflow="fold")
        for r in rows:
            t.add_row(*[str(x) for x in r])
        _console.print(t)
    else:
        print(f"\n== {title} ==")
        print(" | ".join(columns))
        for r in rows:
            print(" | ".join(str(x) for x in r))
        if not rows:
            print("  (none)")


def panel(title: str, body: str, color: str = "cyan") -> None:
    if HAVE_RICH:
        _console.print(Panel(body, title=title, border_style=color))
    else:
        print(f"\n[{title}]\n{body}")
