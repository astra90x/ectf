"""CLI for interacting with the MITRE bootloader

Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from ectf import CONFIG
from ectf.console import debug, error, info, success, warning
from ectf.hw.bootloader import BootloaderError
from ectf.hw.fthr import MAX78000FTHR
from ectf.hw.ti import MSPM0L2228, EraseNeededError, Image, ImageMismatchError

app = typer.Typer()


@app.callback()
def set_port(
    port: Annotated[str, typer.Argument(help="Serial port")],
) -> None:
    """Set the port for the bootloader"""
    CONFIG["PORT"] = port


@app.command("status")
def status_ti() -> None:
    """Get the bootloader status from the MSPM0L2228"""
    board = MSPM0L2228.from_port(CONFIG["PORT"], timeout=3)
    try:
        board.connect()
        status = board.status()
    except BootloaderError as e:
        debug(e)
        error("Could not get status! Reboot board and try again")
        sys.exit(-1)

    success("Successfully got bootloader status:")
    success(
        f" - Version: [cyan]{status.year}.{status.major_version}.{status.minor_version}"
    )
    success(f" - Secure bootloader: {bool(status.secure)}")
    if status.installed is not None:
        success(
            f" - Installed design: {status.installed.decode(errors='backslashreplace')}"
        )
    else:
        success(" - No design installed")
    if not status.app_clear and not status.app_ready:
        warning("Bootloader in unstable state and needs to be erased!")


@app.command("erase")
def erase_ti() -> None:
    """Erase a design from the MSPM0L2228"""
    board = MSPM0L2228.from_port(CONFIG["PORT"], timeout=3)
    try:
        board.connect()
        board.erase()
    except BootloaderError as e:
        debug(e)
        error("Image did not erase! Reboot board and try again")
        sys.exit(-1)
    success("Bootloader erased successfully. The LED should be flashing now")


@app.command("flash")
def flash_ti(
    infile: Annotated[
        Path,
        typer.Argument(help="Path to the file you'd like to flash (e.g., abc.hsm)"),
    ],
    name: Annotated[
        str,  # noqa: RUF013
        typer.Option("--name", "-n", help="Name of the binary"),
    ] = None,
) -> None:
    """Flash a design onto the MSPM0L2228"""
    with (infile / "hsm.bin" if infile.is_dir() else infile).open("rb") as f:
        data = f.read()
    if data.startswith(b"\x7fELF"):
        error(
            "Do not flash the .elf file. It's likely you are looking for the .bin file"
        )
        sys.exit(-1)

    image = Image.deserialize(data, name)

    info(f"Flashing design {image.name}")
    board = MSPM0L2228.from_port(CONFIG["PORT"], timeout=3)
    try:
        board.connect()
        board.flash(image)
    except EraseNeededError as e:
        error(e.args[0])
        sys.exit(-1)
    except ImageMismatchError as e:
        error(e.args[0])
        sys.exit(-1)
    success(
        "Design was successfully flashed."
        " Send start command or reboot to launch new design"
    )


@app.command("start")
def start_ti() -> None:
    """Start the design flashed onto the MSPM0L2228"""
    info("Starting design")
    board = MSPM0L2228.from_port(CONFIG["PORT"], timeout=3)
    try:
        board.connect()
        board.start()
    except BootloaderError as e:
        debug(e)
        error("Image did not start!")
        error(
            "Make sure the board is in bootloader mode by pressing S2/PB21 and "
            "resetting. If that does not work, try erasing, flashing, and starting "
            "again."
        )
        sys.exit(-1)
    success("Loaded image should be running now.")
    success("Reset while holding S2/PB21 to return to bootloader mode.")


@app.command("reflash")
def reflash_ti(
    infile: Annotated[
        Path,
        typer.Argument(help="Path to the build output (e.g., abc.hsm)"),
    ],
    name: Annotated[
        str,  # noqa: RUF013
        typer.Option("--name", "-n", help="Name of the binary"),
    ] = None,
) -> None:
    """Shortcut for erase, flash, then start"""
    with (infile / "hsm.bin" if infile.is_dir() else infile).open("rb") as f:
        data = f.read()
    if data.startswith(b"\x7fELF"):
        error(
            "Do not flash the .elf file. It's likely you are looking for the .bin file"
        )
        sys.exit(-1)

    image = Image.deserialize(data, name)

    info("Reflashing design")
    board = MSPM0L2228.from_port(CONFIG["PORT"], timeout=3)
    try:
        board.connect()
        info("Erasing old design")
        board.erase()
        info("Flashing new design")
        board.flash(image)
        info("Starting new design")
        board.start()
    except EraseNeededError as e:
        error(e.args[0])
        sys.exit(-1)
    except ImageMismatchError as e:
        error(e.args[0])
        sys.exit(-1)
    except BootloaderError as e:
        debug(e)
        error("Reflash unsuccessful!")
        error(
            "Make sure the board is in bootloader mode by pressing S2/PB21 and "
            "resetting. If that does not work, try erasing, flashing, and starting "
            "again."
        )
        sys.exit(-1)
    success("Loaded image should be running now.")
    success("Reset while holding S2/PB21 to return to bootloader mode.")


# TODO: REMOVE BEFORE V1 RELEASE
@app.command("digest")
def digest_ti(
    slot: Annotated[int, typer.Argument(help="Slot of the file")],
) -> None:
    """Get the digest for the given file of the MSPM0L2228"""
    info("Requesting digest")
    board = MSPM0L2228.from_port(CONFIG["PORT"], timeout=3)
    try:
        board.connect()
        digest = board.digest(slot)
    except BootloaderError as e:
        debug(e)
        error(
            "Digest rejected!"
            " This is only available on an Attack board with a design flashed."
        )
        sys.exit(-1)
    success(f"Successfully retrieved digest for slot {slot}.")
    success("Submit the following to the API:")
    success(f"    {digest.hex()}")


@app.command("flash_fthr")
def flash_fthr(
    port: Annotated[str, typer.Argument(help="Serial port")],
    infile: Annotated[
        typer.FileBinaryRead,
        typer.Argument(help="Path to the input image"),
    ],
) -> None:
    """Flash a design onto the MAX78000FTHR"""
    MAX78000FTHR.from_port(port).flash(infile.read())


@app.command("unlock_fthr")
def unlock_fthr(
    port: Annotated[str, typer.Argument(help="Serial port")],
    secrets: Annotated[
        typer.FileBinaryRead,
        typer.Argument(help="Path to the bootloader secrets file"),
    ],
    force: Annotated[
        int,
        typer.Option("--force", "-f", help="I'm sure.", count=True),
    ] = 0,
) -> None:
    """Unlock the secure MITRE bootloader of the MAX78000FTHR"""
    match force:
        case 0:
            sys.exit(
                "Unlocking the board is permanent. You will no longer be able to use"
                " the board to load protected binaries. Are you sure you want to"
                " continue?"
                "\n\nRun again with the --force flag to continue",
            )
        case 1:
            sys.exit(
                "Unlocking the board is permanent. You will no longer be able to use"
                " the board to load protected binaries. Are you sure you want to"
                " continue?"
                "\n\nTHIS IS YOUR LAST CHANCE TO TURN BACK!"
                "\n\nRun again with two --force flags to continue",
            )
        case _:
            secrets = json.loads(secrets.read())
            MAX78000FTHR.from_port(port).unlock(secrets)
