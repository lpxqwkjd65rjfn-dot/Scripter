from __future__ import annotations

import asyncio
from datetime import datetime

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    RichLog,
    SelectionList,
    Static,
)

from .config import AppConfig
from .orchestrator import Orchestrator, ProbeUpdate
from .state import StateStore


class RknProbeApp(App):
    CSS = """
    Screen { layout: vertical; }
    #top { height: 50%; }
    #bottom { height: 50%; }
    SelectionList { width: 30; border: solid $accent; }
    #status { border: solid $secondary; padding: 1; }
    #log { border: solid $primary; }
    #table { border: solid $success; }
    Button { margin: 1; }
    #found { color: $success; text-style: bold; }
    """

    BINDINGS = [
        ("s", "start", "Start"),
        ("x", "stop", "Stop"),
        ("q", "quit", "Quit"),
    ]

    found_ip: reactive[str] = reactive("")

    def __init__(self, config: AppConfig, mock: bool = False) -> None:
        super().__init__()
        self.config = config
        self.mock = mock
        self.state = StateStore(config.global_.state_file)
        self.orch = Orchestrator(config, self.state, mock=mock)
        self._tasks: list[asyncio.Task] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="top"):
            with Horizontal():
                providers = [
                    (name, name, cfg.enabled)
                    for name, cfg in self.config.providers.items()
                ]
                yield SelectionList[str](*providers, id="providers")
                with Vertical():
                    yield Static(self._status_text(), id="status")
                    with Horizontal():
                        yield Button("Start [s]", id="btn-start", variant="success")
                        yield Button("Stop  [x]", id="btn-stop", variant="warning")
                        yield Button("Quit  [q]", id="btn-quit", variant="error")
                    yield Label("", id="found")
        with Vertical(id="bottom"):
            with Horizontal():
                table = DataTable(id="table")
                table.add_columns("time", "provider", "ip", "stage", "ok", "detail")
                yield table
                yield RichLog(id="log", highlight=True, markup=True)
        yield Footer()

    def _status_text(self) -> str:
        mode = "MOCK" if self.mock else "LIVE"
        return (
            f"[b]Mode:[/b] {mode}    "
            f"[b]Providers configured:[/b] {len(self.config.providers)}    "
            f"[b]Whitelisted so far:[/b] {len(self.state.state.whitelisted)}"
        )

    def on_mount(self) -> None:
        self.title = "RKN Whitelist Probe"
        self.sub_title = "Multi-cloud IP whitelist scanner"
        log: RichLog = self.query_one("#log", RichLog)
        log.write("[dim]Ready. Select providers and press Start.[/dim]")

    @on(Button.Pressed, "#btn-start")
    def _on_start(self) -> None:
        self.action_start()

    @on(Button.Pressed, "#btn-stop")
    def _on_stop(self) -> None:
        self.action_stop()

    @on(Button.Pressed, "#btn-quit")
    def _on_quit(self) -> None:
        self.action_quit()

    def action_start(self) -> None:
        sel: SelectionList = self.query_one("#providers", SelectionList)
        selected = list(sel.selected)
        if not selected:
            self.query_one("#log", RichLog).write("[yellow]No providers selected.[/yellow]")
            return
        for name in selected:
            t = asyncio.create_task(self._run_provider(name))
            self._tasks.append(t)
        self.query_one("#log", RichLog).write(
            f"[green]Started:[/green] {', '.join(selected)}"
        )

    def action_stop(self) -> None:
        self.orch.stop()
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
        self.query_one("#log", RichLog).write("[yellow]Stop requested. Releasing IPs...[/yellow]")
        asyncio.create_task(self._cleanup_and_notify())

    async def _cleanup_and_notify(self) -> None:
        await self.orch.cleanup()
        self.query_one("#log", RichLog).write("[green]Cleanup done.[/green]")

    async def _run_provider(self, name: str) -> None:
        try:
            async for upd in self.orch.run_provider(name, self._log_update):
                self._log_update(upd)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self._log_update(ProbeUpdate(name, "error", {"error": str(exc)}))

    def _log_update(self, upd: ProbeUpdate) -> None:
        log: RichLog = self.query_one("#log", RichLog)
        ts = datetime.now().strftime("%H:%M:%S")
        if upd.kind == "stage":
            tbl: DataTable = self.query_one("#table", DataTable)
            ok = "✓" if upd.payload["ok"] else "✗"
            tbl.add_row(
                ts, upd.provider, upd.payload["ip"], upd.payload["stage"], ok, upd.payload["detail"]
            )
        elif upd.kind == "found":
            self.found_ip = upd.payload["ip"]
            self.query_one("#found", Label).update(
                Text.from_markup(f"[b green]FOUND WHITELISTED IP:[/b green] {self.found_ip}  ({upd.provider})")
            )
            log.write(f"[b green]>>> WHITELISTED IP FOUND: {self.found_ip} via {upd.provider} <<<[/b green]")
        elif upd.kind == "error":
            log.write(f"[red]{ts} {upd.provider} ERROR {upd.payload}[/red]")
        elif upd.kind == "killswitch":
            log.write(f"[b red]{ts} {upd.provider} KILLSWITCH: {upd.payload}[/b red]")
        else:
            log.write(f"[dim]{ts}[/dim] {upd.provider} {upd.kind} {upd.payload}")
        self.query_one("#status", Static).update(self._status_text())
