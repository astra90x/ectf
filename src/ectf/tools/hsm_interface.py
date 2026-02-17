"""Interface to the 2026 eCTF HSM

Author: Ben Janis

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import struct
import time
from collections.abc import Iterator, Mapping
from enum import IntEnum
from typing import Any, ClassVar, Self

from attrs import define
from serial import Serial
from serial.serialutil import SerialTimeoutException

from ectf.console import debug, info, warning


class Opcode(IntEnum):
    """Enum class for use in device output processing."""

    LIST = 0x4C  # L
    READ = 0x52  # R
    WRITE = 0x57  # W
    RECEIVE = 0x43  # C
    INTERROGATE = 0x49  # I
    LISTEN = 0x4E  # N
    ACK = 0x41  # A
    DEBUG = 0x44  # D
    ERROR = 0x45  # E


NACK_MSGS = {Opcode.DEBUG, Opcode.ACK}


class TimingRequirementError(Exception):
    """Functional timing requirement failed"""


@define
class MessageHdr:
    """Header for the HSM protocol"""

    MAGIC: ClassVar[bytes] = b"%"

    opcode: Opcode
    size: int

    @classmethod
    def parse(cls, stream: bytes) -> tuple[Self, bytes]:
        """Try to parse a stream of bytes into a MessageHdr

        :param stream: Stream of bytes to parse

        :returns: A tuple with the first parsable MesssageHdr and the remaining bytes
        """
        _, magic, remainder = stream.partition(cls.MAGIC)

        if magic != cls.MAGIC:
            errmsg = "No magic found"
            raise ValueError(errmsg)

        hdr, remainder = remainder[:3], remainder[3:]
        opc, size = struct.unpack("<BH", hdr)
        return cls(Opcode(opc), size), remainder

    def pack(self) -> bytes:
        """Pack the MessageHdr into bytes"""
        return self.MAGIC + struct.pack("<BH", self.opcode, self.size)


@define
class Message:
    """Message for the HSM protocol"""

    BLOCK_LEN: ClassVar[int] = 256

    opcode: Opcode
    body: bytes = b""

    @property
    def hdr(self) -> MessageHdr:
        """Get the header for the message"""
        return MessageHdr(self.opcode, len(self.body))

    def pack(self) -> bytes:
        """Pack the Message into bytes"""
        return self.hdr.pack() + self.body

    def packets(self) -> Iterator[bytes]:
        """Chunk the message into blocks to send to the HSM

        An ACK is expected from the HSM after each block
        """
        yield self.hdr.pack()
        for i in range(0, len(self.body), self.BLOCK_LEN):
            yield self.body[i : i + self.BLOCK_LEN]

    def is_ack(self) -> bool:
        """Return whether the message is an ACK"""
        return self.opcode == Opcode.ACK


class HSMError(Exception):
    """Generic HSM error condition"""


FileTy = tuple[int, int, bytes]


@define
class HSMIntf:
    """Standard asynchronous interface to the HSM

    See https://rules.ectf.mitre.org/2025/getting_started/boot_reference
    """

    ACK: ClassVar[Message] = Message(Opcode.ACK)

    ser: Serial
    stream: bytes = b""
    strict_timing: bool = False

    @classmethod
    def from_port(
        cls,
        port: str,
        baud: int = 115200,
        strict_timing: bool = False,
        **serial_kwargs: Mapping[str, Any],
    ) -> Self:
        """Open a serial port and generate an HSMIntf

        :param port: Serial port to the HSM
        :param baud: Baudrate of HSM
        :param serial_kwargs: Args to pass to the serial interface construction
        """
        ser = Serial(baudrate=baud, **serial_kwargs)
        ser.port = port
        return cls(ser, strict_timing=strict_timing)

    def _open(self) -> None:
        """Open the serial connection if not already opened"""
        if not self.ser.is_open:
            self.ser.open()

    def _send_respond(self, msg: Message, timing_req_ms: int = 0) -> Message:
        start = time.perf_counter_ns()
        self.send_msg(msg)
        resp = self.get_msg()
        end = time.perf_counter_ns()

        # check for bad opcode
        if resp.opcode != msg.opcode:
            raise HSMError(resp)

        # check timing requirements
        duration = (end - start) // 1000000
        if 0 < timing_req_ms < duration:
            err = (
                f"Command exceeded timing requirement! {duration}ms > {timing_req_ms}ms"
            )
            if self.strict_timing:
                raise TimingRequirementError(err)
            warning(err)
        return resp

    def write_file(self, frame: bytes) -> None:
        """Write a file to the HSM

        :param frame: all data to be sent to the HSM as a part of the write command
        :raises HSMError: Error on write failure
        """
        # send write message
        msg = Message(Opcode.WRITE, frame)
        self._send_respond(msg, 3000)

    def read_file(self, frame: bytes) -> bytes:
        """Read a file from the HSM

        :param frame: Data to be sent to the hsm (design-dependent)
        :returns: The data from the file
        :raises HSMError: Error on read failure
        """
        # send read message
        msg = Message(Opcode.READ, frame)
        resp = self._send_respond(msg, 3000)
        return resp.body

    def _unpack_files(self, buf: bytes) -> list[FileTy]:
        # unpack number of files
        nfiles, body = buf[:4], buf[4:]
        nfiles = struct.unpack("<I", nfiles)[0]
        debug(f"Interrogation reported {nfiles} files exist")

        try:
            files = list(struct.iter_unpack("<BH32s", body))
        except struct.error as e:
            msg = "Received invalid files size"
            raise HSMError(msg) from e

        if len(files) != nfiles:
            errmsg = f"Expected {nfiles} files, got {len(files)}"
            raise HSMError(errmsg)

        # unpack channel infos
        return files

    def interrogate(self, pin: str) -> list[FileTy]:
        """Read a file from a neighboring HSM

        :param frame: All data to be sent to the HSM as a part of the request
        :returns: The list of files from the neighboring HSM
        :raises HSMError: Error on interrogate failure
        """
        msg = Message(Opcode.INTERROGATE, pin.encode())
        resp = self._send_respond(msg, 1000)

        return self._unpack_files(resp.body)

    def listen(self) -> None:
        """Put the HSM in listen mode

        :raises HSMError: Error on listen failure
        """
        msg = Message(Opcode.LISTEN)
        self._send_respond(msg)  # no explicit timing requirement

    def receive(self, frame: bytes) -> bytes:
        """Receive a file from a neighboring HSM

        :param frame: The frame to be sent to the local HSM
        :returns: The body of the response from the HSM,
            usually success or error
        :raises HSMError: Error on receive failure
        """
        msg = Message(Opcode.RECEIVE, frame)
        resp = self._send_respond(msg, 3000)
        return resp.body

    # this may need to change depending on how we define it...
    # name printing mostly
    def list(self, pin: str) -> list[FileTy]:
        """List the files on an HSM

        :param pin: The pin to authenticate to the HSM
        :returns: A list of tuples containing the existing file names and their
            group ids
        :raises HSMError: Error on list failure
        """
        # send list message
        msg = Message(Opcode.LIST, pin.encode())
        resp = self._send_respond(msg, 500)

        return self._unpack_files(resp.body)

    def send_ack(self) -> None:
        """Send an ACK to the HSM"""
        self._open()
        self.ser.write(self.ACK.pack())

    def get_ack(self) -> None:
        """Get an expected ACK from the HSM

        :raises HSMError: Non-ACK response was received (other than DEBUGs)
        """
        msg = self.get_msg()
        if msg != self.ACK:
            errmsg = f"Got bad ACK {msg}"
            raise HSMError(errmsg)

    def try_parse(self) -> MessageHdr | None:
        """Try to parse the input stream into a MessageHdr

        :returns: The MessageHdr if the parse was successful, None otherwise
        """
        try:
            hdr, self.stream = MessageHdr.parse(self.stream)
        except (ValueError, struct.error):
            return None
        debug(f"Found header {hdr}")
        return hdr

    def get_raw_msg(self) -> Message:
        """Get a message, blocking until full message received

        :returns: Message received by HSM
        :raises: HSMError if unexpected behavior encountered
        """
        self._open()
        while (hdr := self.try_parse()) is None:
            b = self.ser.read(1)
            if b == b"":
                errmsg = "Read timeout"
                raise SerialTimeoutException(errmsg)
            self.stream += b

        # Don't ACK an ACK or a debug message
        if hdr.opcode not in NACK_MSGS:
            self.send_ack()

        remaining = hdr.size
        body = b""
        while remaining > 0:
            block = b""
            while block_remaining := min(Message.BLOCK_LEN, remaining) - len(block):
                b = self.ser.read(block_remaining)
                if b == b"":
                    errmsg = "Read timeout"
                    raise SerialTimeoutException(errmsg)
                block += b

            # Don't ACK an ACK or a debug message
            if hdr.opcode not in NACK_MSGS:
                self.send_ack()

            debug(f"Read block {block!r}")
            body += block
            remaining -= len(block)
        msg = Message(hdr.opcode, body)
        debug(f"Got message {msg}")
        return msg

    def get_msg(self) -> Message:
        """Get a message, handling DEBUG and ERROR messages

        :returns: Message received by HSM, filtering DEBUGs
        :raises HSMError: If unexpected behavior or ERROR message encountered
        """
        while True:
            msg = self.get_raw_msg()

            if msg.opcode == Opcode.ERROR:
                raise HSMError(msg)

            if msg.opcode != Opcode.DEBUG:
                return msg

            info(f"Got DEBUG message: {msg.body!r}")

    def send_msg(self, msg: Message) -> None:
        """Send a message to the HSM

        :param msg: Message to send
        :raises HSMError: If unexpected behavior or ERROR message encountered
        """
        self._open()
        debug(f"Sending message {msg}")
        for packet in msg.packets():
            debug(f"Sending packet {packet}")
            self.ser.write(packet)
            self.get_ack()
