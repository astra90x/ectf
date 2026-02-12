"""CLI for the 2026 eCTF Host tools

Author: Ben Janis

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import sys
from http import HTTPStatus
from pathlib import Path
from typing import Annotated

import typer
from requests import RequestException

from ectf.api import API
from ectf.api.api_interface import APIError, handle_api_exception
from ectf.api.flow import flow_submit, gen_flow_app
from ectf.console import error, info, success

app = typer.Typer()

clone_app = gen_flow_app("clone", typer.Typer(), "update")
test_app = gen_flow_app("test", typer.Typer(), "update")
submit_app = gen_flow_app("submit", typer.Typer(), "submit")
remote_app = gen_flow_app("remote", typer.Typer())
app.add_typer(
    clone_app, name="clone", help="Test that your design can be cloned by the API"
)
app.add_typer(test_app, name="test", help="Test your design with the API")
app.add_typer(submit_app, name="submit", help="Submit your design to Handoff")
app.add_typer(remote_app, name="remote", help="Submit to the remote attack scenario")


@app.command()
def submit(
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
        error(err_msg)
        sys.exit(-1)
    flow_submit(
        "submit",
        {"git_url": url, "commit_hash": commit},
        {HTTPStatus.BAD_REQUEST: "Your team has already submitted a design!"},
    )


@app.command("photo")
def flag_photo(
    photo: Annotated[
        typer.FileBinaryRead, typer.Argument(help="Path to the PNG photo")
    ],
) -> None:
    """Submit a PNG for the Team Photo flag"""
    if not photo.name.lower().endswith(".png"):
        error(f"Photo {photo.name} is not a PNG! Please resubmit with a PNG")
        sys.exit(-1)

    try:
        flag = API.submit_flag_file("team_photo", photo)
    except (APIError, RequestException) as e:
        handle_api_exception(e, {HTTPStatus.UNPROCESSABLE_ENTITY: "File is not a PNG!"})
    success("Congrats! Your photo was accepted! Please submit the following flag:")
    info(flag)


@app.command("design")
def flag_design(
    design: Annotated[
        typer.FileBinaryRead, typer.Argument(help="Path to the design doc PDF")
    ],
) -> None:
    """Submit a PDF for the Design Doc flag"""
    if not design.name.lower().endswith(".pdf"):
        error(f"Design doc {design.name} is not a PDF! Please resubmit with a PDF")
        sys.exit(-1)

    try:
        flag = API.submit_flag_file("design_doc", design)
    except (APIError, RequestException) as e:
        handle_api_exception(e, {HTTPStatus.UNPROCESSABLE_ENTITY: "File is not a PDF!"})
    success("Congrats! Your design doc was accepted! Please submit the following flag:")
    info(flag)


@app.command("steal")
def flag_steal(
    team: Annotated[str, typer.Argument(help="Team being attacked")],
    digest: Annotated[str, typer.Argument(help="Digest of the stolen flag")],
) -> None:
    """Submit a digest for the Steal Design flag"""
    try:
        flag = API.submit_flag(f"steal_design/{team}", digest)
    except (APIError, RequestException) as e:
        handle_api_exception(
            e,
            {HTTPStatus.BAD_REQUEST: f"Provided hash is incorrect for team {team}!"},
        )

    success("Congrats! The hash was correct! Please submit the following flag:")
    info(flag)


@app.command("list")
def package_list() -> None:
    """Get the list of available packages"""
    try:
        packages = API.list_packages()
    except (APIError, RequestException) as e:
        handle_api_exception(e)

    info("The following packages are available:")
    for package in packages:
        info(f"\t{package}")


@app.command("get")
def package_get(
    package: Annotated[str, typer.Argument(help="Name of package to download")],
    out: Annotated[
        Path,  # noqa: RUF013
        typer.Option(help="Path to output file. Default is ./<package>.enc"),
    ] = None,
    force: Annotated[  # noqa: FBT002
        bool,
        typer.Option("--force", "-f", help="Overwrite output file if it exists"),
    ] = False,
) -> None:
    """Download an Attack Package"""
    if package.endswith((".zip", ".enc")):
        error(
            f"package: {package} should not include any file suffix"
            " (e.g. 'package' instead of 'package.enc')"
        )
        sys.exit(-1)

    if out is None:
        out = Path() / f"{package}.enc"

    try:
        with out.open("wb" if force else "xb") as f:
            for chunk in API.get_package(package):
                f.write(chunk)
    except FileExistsError:
        error(
            f"File {out.absolute()} already exists! Change output path using --out"
            " or overwrite with --force",
        )
        sys.exit(-1)
    except (APIError, RequestException) as e:
        custom = {
            HTTPStatus.NOT_FOUND: f"Package {package} not found!"
            " Use `ectf package list` to list all valid packages"
        }
        handle_api_exception(e, custom)
    success(f"Wrote package to {out.absolute()}")
