"""CLI for the 2026 eCTF Host tools

Author: Ben Janis

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import struct
import sys
from pathlib import Path
from typing import Annotated
from uuid import uuid4

import typer

from ectf import CONFIG
from ectf.console import debug, error, info, success
from ectf.tools.hsm_interface import HSMError, HSMIntf

app = typer.Typer()

MAX_FILE_COUNT = 8
PIN_LEN = 6
GROUP_BITLEN = 16
MAX_NAME_LEN = 32
MAX_FILE_LEN = 8192
UUID_LEN = 16


def dec_or_hex_int(value: int) -> int:
    """Int decode function for clearer typer help message"""
    return int(value, 0)


PortArgTy = Annotated[str, typer.Argument(help="Serial port")]
PINArgTy = Annotated[
    str,
    typer.Argument(help=f"The {PIN_LEN} digit pin to authenticate the HSM device"),
]
SlotArgTy = Annotated[
    int,
    typer.Argument(help="The slot on the device for the file", min=0, max=7),
]
GIDArgTy = Annotated[
    int,
    typer.Argument(
        help="ID of the group that owns the HSM file",
        parser=dec_or_hex_int,
        min=0,
        max=0xFFFF,
    ),
]
UUIDArgTy = Annotated[
    str,
    typer.Option(
        "--uuid",
        "-u",
        help="UUID of the file",
        default_factory=lambda: uuid4().hex,  # if unspecified, generate a random UUID
    ),
]


@app.callback()
def set_port(
    port: Annotated[str, typer.Argument(help="Serial port")],
) -> None:
    """Set the port for the HSM"""
    CONFIG["PORT"] = port


@app.command()
def read(
    pin: PINArgTy,
    slot: SlotArgTy,
    read_file_path: Annotated[Path, typer.Argument(help="Path to write the file to")],
    force: Annotated[bool, typer.Option("--force", "-f")] = False,  # noqa: FBT002
) -> None:
    """Read a file stored on the HSM"""
    hsm = HSMIntf.from_port(CONFIG["PORT"])

    frame = struct.pack(f"<{PIN_LEN}sB", pin.encode(), slot)

    try:
        file_data = hsm.read_file(frame)
    except HSMError as e:
        debug(e)
        error(f"HSM failed with error: {e.args[0]!r}")
        sys.exit(-1)

    # should be an object matching name (null terminated) + contents
    name, contents = file_data[:32].rstrip(b"\x00"), file_data[32:]

    # Write the results to a file
    full_path = read_file_path / name.decode("utf-8")
    with Path.open(full_path, "wb" if force else "xb") as f:
        f.write(contents)

    success(f"Read successful. Wrote file to {full_path.absolute()!s}")


@app.command()
def write(
    pin: PINArgTy,
    slot: SlotArgTy,
    gid: GIDArgTy,
    file: Annotated[
        typer.FileBinaryRead,
        typer.Argument(help="Path to a file on the host filesystem to send to the HSM"),
    ],
    uuid: UUIDArgTy,
) -> None:
    """Write a file stored to the HSM"""
    hsm = HSMIntf.from_port(CONFIG["PORT"])
    file_contents = file.read()

    # Package the frame and run write
    frame = struct.pack(
        f"<{PIN_LEN}sBH{MAX_NAME_LEN}s{UUID_LEN}sH",
        pin.encode(),
        slot,
        gid,
        Path(file.name).name.encode(),
        bytes.fromhex(uuid),
        len(file_contents),
    )
    frame += file_contents
    try:
        hsm.write_file(frame)
    except HSMError as e:
        debug(e)
        error(f"HSM failed with error: {e.args[0]!r}")
        sys.exit(-1)

    success("Write successful")


@app.command()
def receive(
    pin: PINArgTy,
    read_slot: SlotArgTy,
    write_slot: SlotArgTy,
) -> None:
    """Receive a file stored on another HSM"""
    hsm = HSMIntf.from_port(CONFIG["PORT"])

    frame = struct.pack(
        f"<{PIN_LEN}sBB",
        pin.encode(),
        read_slot,
        write_slot,
    )
    try:
        hsm.receive(frame)
    except HSMError as e:
        debug(e)
        error(f"HSM failed with error: {e.args[0]!r}")
        sys.exit(-1)

    success(f"Receive successful. Wrote file to local slot {write_slot}")


@app.command()
def listen() -> None:
    """Alert the HSM to listen for another HSM"""
    try:
        HSMIntf.from_port(CONFIG["PORT"]).listen()
    except HSMError as e:
        debug(e)
        error(f"HSM failed with error: {e.args[0]!r}")
        sys.exit(-1)
    success("Listen successful")


@app.command("list")
def list_(pin: PINArgTy) -> None:
    """List the files stored on the current HSM"""
    hsm = HSMIntf.from_port(CONFIG["PORT"])

    try:
        file_list = hsm.list(pin)
    except HSMError as e:
        debug(e)
        error(f"HSM failed with error: {e.args[0]!r}")
        sys.exit(-1)

    for slot, groupid, name in file_list:
        info(f"Found file: Slot {slot:x}, Group {groupid:x}, {name.decode()}")

    success("List successful")


@app.command()
def interrogate(pin: PINArgTy) -> None:
    """Interrogate files stored on a connected HSM"""
    hsm = HSMIntf.from_port(CONFIG["PORT"])

    try:
        file_list = hsm.interrogate(pin)
    except HSMError as e:
        debug(e)
        error(f"HSM failed with error: {e.args[0]!r}")
        sys.exit(-1)

    for slot, groupid, name in file_list:
        info(f"Found remote file: Slot {slot:x}, Group {groupid:x}, {name.decode()}")

    success("Interrogate successful")
