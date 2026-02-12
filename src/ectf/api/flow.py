"""CLI to interact with the eCTF API's flow infrastructure

Author: Ben Janis

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import json
import sys
from http import HTTPStatus
from json import JSONDecodeError
from typing import Annotated

import typer
from requests import RequestException
from rich.table import Table

from ectf.api import API
from ectf.api.api_interface import APIError, CustomHandlerTy, handle_api_exception
from ectf.console import error, info, success


def gen_flow_app(flow: str, app: typer.Typer, *exclude: str) -> typer.Typer:
    """Generate a typer app for a flow interface

    :param flow: Lowercase name of the flow
    :param app: App to add commands to
    :param exclude: Exclude adding default commands
    :return: The modified typer app
    """
    f_cap = flow.capitalize()

    if "ls" not in exclude:

        @app.command("ls")
        def _list(
            number: Annotated[
                int,
                typer.Option(
                    "--number",
                    "-n",
                    help="Number of flows to list (0 lists all flows)",
                    min=0,
                ),
            ] = 5,
        ) -> None:
            """List the submitted flows"""
            flow_list(flow, number)

    if "info" not in exclude:

        @app.command("info")
        def _info(
            test_id: Annotated[str, typer.Argument(help=f"{f_cap} ID to query")],
        ) -> None:
            """Get the full information for a single submitted flow"""
            flow_info(flow, test_id)

    if "submit" not in exclude:

        @app.command("submit")
        def _submit(
            commit: Annotated[str, typer.Argument(help="Git commit to submit")],
            url: Annotated[
                str,  # noqa: RUF013
                typer.Option(help="URL of git repo (defaults to config file)"),
            ] = None,
        ) -> None:
            """Submit a commit to the API"""
            url = API.config.git_url if url is None else url
            if url.startswith("https"):
                err_msg = (
                    "Please do not clone with HTTPS, "
                    "instead clone with SSH, edit your url with ectf config -f"
                )
                error(err_msg)
                sys.exit(-1)
            if url.startswith("ssh://") and ":" in url[6:]:
                err_msg = (
                    "When using ssh:// in the url that follows make sure to "
                    'replace ":" with "/", edit your url with ectf config -f'
                )
            flow_submit(flow, {"git_url": url, "commit_hash": commit})

    if "cancel" not in exclude:

        @app.command("cancel")
        def _cancel(
            flow_id: Annotated[str, typer.Argument(help="Flow ID to query")],
        ) -> None:
            """Cancel a pending or incomplete flow"""
            flow_cancel(flow, flow_id)

    if "get" not in exclude:

        @app.command("get")
        def _get(
            job_id: Annotated[str, typer.Argument(help="Job ID to query")],
            out: Annotated[
                typer.FileBinaryWrite,
                typer.Argument(help="Path to the output zip file for job results"),
            ],
        ) -> None:
            """Get the output of a single job"""
            flow_get(flow, job_id, out)

    if "update" not in exclude:

        @app.command("update")
        def test_update(
            job_id: Annotated[str, typer.Argument(help="Job ID to query")],
            args: Annotated[
                typer.FileText,
                typer.Argument(help="Path to the JSON file containing the arguments"),
            ],
        ) -> None:
            """Update a job pending input"""
            flow_update(flow, job_id, args)

    return app


def flow_list(flow: str, number: int, custom: CustomHandlerTy = None) -> None:
    """List the submitted flows"""
    f_cap = flow.capitalize()
    try:
        flows = API.flow_list(flow, number)
    except (APIError, RequestException) as e:
        handle_api_exception(e, custom)

    table = Table(title=f"Submitted {f_cap} Flows")
    table.add_column(f"{f_cap} ID", style="bright_yellow")
    table.add_column("When Submitted", style="cyan")
    table.add_column("Status", style="cyan", max_width=9)
    flows.reverse()
    for flow_ in flows:
        time = flow_.time.humanize()
        table.add_row(flow_.id, time, flow_.status)
    info(table)


def flow_info(flow: str, flow_id: str, custom: CustomHandlerTy = None) -> None:
    """Get the full information for a single submitted flow"""
    f_cap = flow.capitalize()
    try:
        flow = API.flow_info(flow, flow_id)
    except (APIError, RequestException) as e:
        defaults = {
            HTTPStatus.NOT_FOUND: f"{f_cap} {flow_id} not found!"
            f" Check `ectf {flow} list`",
            HTTPStatus.UNPROCESSABLE_ENTITY: f"ID [bright_yellow]{flow_id}[/]"
            f" is not a valid {f_cap} ID! Check `ectf {flow} list`",
        }
        if custom is not None:
            defaults.update(custom)
        handle_api_exception(e, defaults)

    info(flow.tree())


def flow_submit(flow: str, body: dict | tuple, custom: CustomHandlerTy = None) -> None:
    """Submit a flow to be run"""
    try:
        flow_id = API.flow_submit(flow, body)
    except (APIError, RequestException) as e:
        handle_api_exception(e, custom)

    success(f"Successfully submitted {flow} with ID: {flow_id}")


def flow_cancel(flow: str, flow_id: str, custom: CustomHandlerTy = None) -> None:
    """Cancel a non-completed flow"""
    f_cap = flow.capitalize()
    try:
        API.flow_cancel(flow, flow_id)
    except (APIError, RequestException) as e:
        defaults = {
            HTTPStatus.NOT_FOUND: f"{f_cap} {flow_id} not found!"
            f" Check `ectf {flow} list`",
            HTTPStatus.UNPROCESSABLE_ENTITY: f"ID [bright_yellow]{flow_id}[/]"
            f" is not a valid {flow} ID! Check `ectf {flow} list`",
            HTTPStatus.BAD_REQUEST: "Cannot cancel!"
            f" {f_cap} {flow_id} has already completed",
        }
        if custom is not None:
            defaults.update(custom)
        handle_api_exception(e, defaults)

    success(f"Successfully canceled {flow} {flow_id}")


def flow_get(
    flow: str,
    job_id: str,
    out: typer.FileBinaryWrite,
    custom: CustomHandlerTy = None,
) -> None:
    """Get the output of a single job"""
    try:
        for chunk in API.flow_pull(flow, job_id):
            out.write(chunk)
    except (APIError, RequestException) as e:
        defaults = {
            HTTPStatus.NOT_FOUND: f"Job {job_id} not found! Check `ectf {flow} list`",
            HTTPStatus.UNPROCESSABLE_ENTITY: f"ID [bright_yellow]{job_id}[/]"
            f" is not a valid job ID! Check `ectf {flow} list`",
        }
        if custom is not None:
            defaults.update(custom)
        handle_api_exception(e, defaults)

    success(f"Job contents written to {out.name}")


def flow_update(
    flow: str,
    flow_id: str,
    job_id: str,
    args: typer.FileText,
    custom: CustomHandlerTy = None,
) -> None:
    """Update a job pending input"""
    try:
        args_data = json.load(args)
    except JSONDecodeError:
        error(f"File {args.name} is not a valid JSON file")
        sys.exit(-1)

    try:
        API.flow_update(flow, flow_id, job_id, args_data)
    except (APIError, RequestException) as e:
        defaults = {
            HTTPStatus.BAD_REQUEST: "Cannot update!"
            f" Job {job_id} is not in the pending state",
            HTTPStatus.NOT_FOUND: f"Job {job_id} not found! Check `ectf {flow} list`",
            HTTPStatus.UNPROCESSABLE_ENTITY: f"ID [bright_yellow]{job_id}[/]"
            f" is not a valid job ID! Check `ectf {flow} list`",
        }
        if custom is not None:
            defaults.update(custom)
        handle_api_exception(e, defaults)

    success(f"Successfully updated job {job_id}")
