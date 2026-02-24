"""Remote scenario interface

Author: Sam Meyers

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

from __future__ import annotations

import io
import socket
import sys
import threading
import time
import zipfile

import serial
import typer
from attrs import define, field, frozen
from requests import RequestException

from ectf.api import API
from ectf.api.api_interface import APIError, Flow, Job, Status, handle_api_exception
from ectf.api.flow import gen_flow_app
from ectf.console import console, error, info, success
from ectf.tools.hsm_interface import HSMIntf

FLOW_NAME = "remote"
REMOTE_TCP_HOST = "54.163.176.58"

SERIAL_BAUD = 115200


def _find_job(flow: Flow, name: str) -> Job | None:
    target = name.strip().lower()
    for job in flow.jobs:
        if job.name.strip().lower() == target:
            return job
    return None


def _read_port_from_zip(zip_bytes: bytes) -> int:
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        target = None
        for n in zf.namelist():
            if n.endswith("port.out"):
                target = n
                break
        if target is None:
            error("port.out not found in get_ports output zip")
            sys.exit(-1)
        raw = zf.read(target).decode("utf-8", errors="ignore").strip()

    port = int(raw)
    if not (1 <= port <= 65535):  # noqa: PLR2004
        error(f"Invalid TCP port in port.out: {port}")
        sys.exit(-1)
    return port


@frozen
class RemoteScenarioConfig:
    """Config object to specify arguments to the remote scenario"""

    management_port: str
    transfer_port: str
    team: str
    timeout_seconds: float = 120.0
    verbose: bool = False


@define
class RemoteScenarioIntf:
    """Interface to the remote scenario using the eCTF API"""

    cfg: RemoteScenarioConfig
    _stop: threading.Event = field(factory=threading.Event)

    _tcp: socket.socket | None = None
    _xfer: serial.Serial | None = None
    _hsm: HSMIntf | None = None

    _flow_id: str | None = None

    _threads: list[threading.Thread] = field(factory=list)

    def run(self) -> None:
        """Run the remote scenario"""
        try:
            tcp_port = self._prepare_remote_infrastructure()
            self._bridge(tcp_port)
        finally:
            self._stop.set()

    def _prepare_remote_infrastructure(self) -> int:  # noqa: PLR0915
        info(f"Submitting remote flow for team: [bright_yellow]{self.cfg.team}[/]")

        try:
            flow_id = API.flow_submit(FLOW_NAME, {"target_team": self.cfg.team})
            # remove the quotes from the response
            flow_id = flow_id.rstrip('"').lstrip('"')
            self._flow_id = flow_id
        except (APIError, RequestException) as e:
            handle_api_exception(e)

        success(f"Submitted remote flow with ID: {flow_id}")
        info(
            "Waiting for get_ports to succeed and run_remote_scenario to enter running "
            "state..."
        )

        port: int | None = None
        last_line = ""

        # let's wait 25 minutes
        infra_deadline = time.monotonic() + (60.0 * 25.0)

        while True:
            if time.monotonic() >= infra_deadline:
                error("Timed out waiting for remote infrastructure to become ready.")
                sys.exit(-1)

            try:
                flow = API.flow_info(FLOW_NAME, flow_id)
            except (APIError, RequestException) as e:
                handle_api_exception(e)

            get_ports_job = _find_job(flow, "get_ports")
            run_job = _find_job(flow, "run_remote_scenario")

            if get_ports_job is None or run_job is None:
                available = ", ".join(j.name for j in flow.jobs)
                error(
                    "Remote flow schema did not include expected jobs "
                    "(get_ports, run_remote_scenario). "
                    f"Available jobs: {available}"
                )
                sys.exit(-1)

            line = (
                f"get_ports={get_ports_job.status.name}  "
                f"run_remote_scenario={run_job.status.name}"
            )
            if line != last_line:
                info(line)
                if port is not None and run_job.status == Status.QUEUED:
                    info(
                        "Remote scenario queued. Waiting for available hardware. This "
                        "may take some time."
                    )
                last_line = line

            if get_ports_job.status in (Status.FAILED, Status.CANCELED):
                error("get_ports job failed/canceled.")
                sys.exit(-1)

            if run_job.status in (Status.FAILED, Status.CANCELED):
                error("run_remote_scenario job failed/canceled.")
                sys.exit(-1)

            if port is None and get_ports_job.status == Status.SUCCEEDED:
                buf = io.BytesIO()
                try:
                    for chunk in API.flow_pull(FLOW_NAME, get_ports_job.id):
                        buf.write(chunk)
                except (APIError, RequestException) as e:
                    handle_api_exception(e)

                try:
                    port = _read_port_from_zip(buf.getvalue())
                except Exception as e:  # noqa: BLE001
                    error(f"Failed to parse get_ports output: {e}")
                    sys.exit(-1)

                success(f"Remote TCP port: {port}")

            if port is not None and run_job.status == Status.RUNNING:
                return port

            time.sleep(1.0)

    def _bridge(self, tcp_port: int) -> None:
        self._xfer = serial.Serial(
            port=self.cfg.transfer_port,
            baudrate=SERIAL_BAUD,
            timeout=0,
        )

        self._hsm = HSMIntf.from_port(self.cfg.management_port)

        t_listen = threading.Thread(
            target=self._listen_loop,
            name="remote-listen",
            daemon=True,
        )
        t_listen.start()
        self._threads.append(t_listen)

        info(f"Connecting to remote TCP: {REMOTE_TCP_HOST}:{tcp_port}.")
        self._tcp = self._connect_tcp(REMOTE_TCP_HOST, tcp_port)
        success("TCP connected; starting UART<->TCP forwarding")
        scenario_end_time = time.monotonic() + self.cfg.timeout_seconds

        t_a = threading.Thread(
            target=self._pump_tcp_to_serial, name="tcp->serial", daemon=True
        )
        t_b = threading.Thread(
            target=self._pump_serial_to_tcp, name="serial->tcp", daemon=True
        )
        t_a.start()
        t_b.start()
        self._threads.extend([t_a, t_b])

        try:
            while not self._stop.is_set():
                if time.monotonic() >= scenario_end_time:
                    info("scenario_end_time reached; stopping.")
                    self._stop.set()
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            info("Interrupted; stopping.")
            self._stop.set()

    def _connect_tcp(self, host: str, port: int) -> socket.socket:
        delay = 1
        while not self._stop.is_set():
            try:
                s = socket.create_connection((host, port), timeout=5)
                s.settimeout(None)
                return s  # noqa: TRY300
            except OSError:
                console.print(".", end="")
                flow = API.flow_info(FLOW_NAME, self._flow_id)
                job_status = _find_job(flow, "run_remote_scenario").status
                if job_status in [Status.FAILED, Status.CANCELED]:
                    error(f"Job ended with status {job_status.name}. Exiting")
                    sys.exit(-1)

                time.sleep(delay)
                delay = min(delay * 1.5, 2.0)
        error("Failed to connect to remote scenario TCP port")
        sys.exit(-1)

    def _listen_loop(self) -> None:
        assert self._hsm is not None
        while not self._stop.is_set():
            try:
                self._hsm.listen()
                time.sleep(1)
            except Exception as e:  # noqa: BLE001
                error(f"Exception {e} in listen thread")
                self._stop.set()
                return

    def _pump_tcp_to_serial(self) -> None:
        assert self._tcp is not None
        assert self._xfer is not None
        try:
            while not self._stop.is_set():
                data = self._tcp.recv(1024)
                if not data:
                    info("Remote end disconnected. Scenario complete.")
                    self._stop.set()
                    return
                if self.cfg.verbose:
                    info(
                        "[bold cyan]TCP[/bold cyan]->[bold yellow]UART[/bold yellow]: "
                        f"[bright_white]{data}[/bright_white]"
                    )
                self._xfer.write(data)
        except Exception as e:  # noqa: BLE001
            error(f"Exception {e} while forwarding TCP->serial")
            self._stop.set()

    def _pump_serial_to_tcp(self) -> None:
        assert self._tcp is not None
        assert self._xfer is not None
        try:
            while not self._stop.is_set():
                data = self._xfer.read(1024)
                if data == b"":
                    continue
                if self.cfg.verbose:
                    info(
                        "[bold yellow]UART[/bold yellow]->[bold cyan]TCP[/bold cyan]: "
                        f"[bright_white]{data}[/bright_white]"
                    )
                self._tcp.sendall(data)
        except Exception as e:  # noqa: BLE001
            error(f"Exception {e} while forwarding serial->TCP")
            self._stop.set()


remote_app = typer.Typer(
    add_completion=False,
    help="Submit to and interact with the remote attack scenario.",
)

remote_app = gen_flow_app(FLOW_NAME, remote_app, "submit", "update")


@remote_app.command("connect")
def connect_remote(
    management_port: str = typer.Argument(
        ..., help="Serial port for HSM management interface"
    ),
    transfer_port: str = typer.Argument(
        ..., help="Serial port for Transfer Interface UART"
    ),
    team: str = typer.Argument(..., help="Target team identifier for remote scenario"),
    timeout: float = typer.Option(
        120.0,
        "--timeout",
        "-t",
        help=(
            "How long (in seconds) to keep issuing listen() / forwarding before "
            "exiting."
        ),
    ),
    verbose: bool = typer.Option(  # noqa: FBT001
        False,  # noqa: FBT003
        "--verbose",
        "-v",
        help=("Verbose output for debugging"),
    ),
) -> None:
    """Run the full remote scenario"""
    cfg = RemoteScenarioConfig(
        management_port=management_port,
        transfer_port=transfer_port,
        team=team.lower(),
        timeout_seconds=timeout,
        verbose=verbose,
    )
    RemoteScenarioIntf(cfg).run()
