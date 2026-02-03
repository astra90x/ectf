"""Interface to the eCTF API

Author: Ben Janis

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import sys
from collections.abc import Callable, Hashable, Iterator
from enum import IntEnum, auto
from functools import singledispatch
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from typing import ClassVar, NoReturn, Self

import arrow
import requests
import yaml
from attrs import define, field, frozen
from requests import Request, RequestException
from requests.auth import AuthBase
from rich.tree import Tree

from ectf.console import debug, error


class APIError(Exception):
    """Error caused by a failure in the API"""

    def __init__(self, response: requests.Response):  # noqa: D107
        super().__init__(f"API responded with status {response.status_code}")
        self.response = response
        self.status = response.status_code


CustomHandlerTy = dict[Hashable, str] | None


@singledispatch
def handle_api_exception(e: Exception, custom: CustomHandlerTy = None) -> NoReturn:
    """Handle common API exceptions and exit"""


@handle_api_exception.register(APIError)
def _(e: APIError, custom: dict[Hashable, str] | None = None) -> NoReturn:
    if custom is not None and e.status in custom:
        error(custom[e.status])
        sys.exit(-1)

    match e.status:
        case HTTPStatus.UNAUTHORIZED:
            error("Token rejected! Use `ectf config` to set token")
        case HTTPStatus.FORBIDDEN:
            error("Your team must be in the Attack Phase to use this API")
        case HTTPStatus.INTERNAL_SERVER_ERROR:
            error(f"Internal server error! Please contact organizers: {e.status}")
        case HTTPStatus.CONFLICT:
            error(
                "Reached max active flows!"
                " Please cancel them or wait for them to finish before submitting"
            )
        case _:
            error(f"Unexpected response {e.status}! Please contact organizers")
    sys.exit(-1)


@handle_api_exception.register(RequestException)
def _(e: APIError, _: dict[Hashable, str] | None = None) -> NoReturn:
    error(f"Could not connect to API! Please contact organizers: {e}")
    sys.exit(-1)


@define
class Config:
    """Representation of the Config file"""

    token: str = field(default=None, repr=False)
    git_url: str = None
    api_url: str = "https://api.ectf.mitre.org"

    PATH: ClassVar[Path] = (Path.home() / ".ectf-config").absolute()

    @classmethod
    def exists(cls) -> bool:
        """Check if the Config file exists"""
        return cls.PATH.exists()

    @classmethod
    def load(cls) -> Self:
        """Load the Config from the file"""
        if not cls.exists():
            return cls()

        with cls.PATH.open("r") as f:
            config = yaml.safe_load(f)

        return cls(
            config["token"],
            config["git_url"],
            config["api_url"],
        )

    def dump(self) -> None:
        """Dump the Config to a file"""
        with self.PATH.open("w") as f:
            yaml.safe_dump(
                {"token": self.token, "git_url": self.git_url, "api_url": self.api_url},
                f,
            )

    @property
    def configured(self) -> bool:
        """Check if Config is configured or empty"""
        return not (self.token is None or self.git_url is None or self.api_url is None)

    def assert_configured(self) -> None:
        """Assert that the Config is configured and exit if not"""
        if not self.configured:
            error("Config file does not yet exist! Use `ectf config` to generate")
            sys.exit(-1)


class HTTPBearerAuth(AuthBase):
    """Bearer token authentication"""

    def __init__(self, token: str):  # noqa: D107
        self.token = token

    def __eq__(self, other: AuthBase) -> bool:
        """Check for equality of a token"""
        return self.token == getattr(other, "token", None)

    def __ne__(self, other: AuthBase) -> bool:
        """Check for non-equality of a token"""
        return not self == other

    def __call__(self, r: Request) -> Request:
        """Generate the bearer token"""
        r.headers["Authorization"] = "Bearer " + self.token
        return r


class Status(IntEnum):
    """Status of a Job or Flow"""

    QUEUED = auto()
    SUCCEEDED = auto()
    RUNNING = auto()
    PENDING = auto()
    CANCELED = auto()
    FAILED = auto()

    def __rich__(self) -> str:
        """Format the status for rich"""
        match self:
            case Status.QUEUED:
                return "[magenta]Queued"
            case Status.RUNNING:
                return "[bright_cyan]Running"
            case Status.PENDING:
                return "[orange1]Pending"
            case Status.SUCCEEDED:
                return "[green]Succeeded"
            case Status.CANCELED:
                return "[white]Canceled"
            case Status.FAILED:
                return "[bold red]Failed"
            case _:
                raise ValueError("Huh?")  # noqa: EM101


@frozen
class Job:
    """The state of an API Job"""

    name: str
    id: str
    has_artifacts: bool
    private: bool
    status: Status

    @classmethod
    def from_dict(cls, job: dict) -> Self:
        """Create a Job from the API JSON return"""
        return cls(
            job["name"],
            job["id"],
            job["has_artifacts"],
            job["private"],
            Status[job["status"].upper()],
        )

    def tree(self) -> Tree:
        """Generate a rich tree of the Job"""
        tree = Tree(self.name, highlight=True)
        tree.add(f"ID: {self.id}")
        tree.add(f"Has Output: {self.has_artifacts}")
        tree.add(f"Private: {self.private}")
        tree.add(f"Status: {self.status.__rich__()}")
        return tree


@frozen
class Flow:
    """The state of an API Flow"""

    id: str
    time: arrow.Arrow
    name: str
    status: Status
    params: dict[str, str]
    jobs: list[Job]

    @classmethod
    def from_dict(cls, flow: dict) -> Self:
        """Create a Flow from the API JSON return"""
        time = arrow.get(flow["submit_time"])
        jobs = [Job.from_dict(job) for job in flow["jobs"]]
        status = max(job.status for job in jobs)
        return cls(flow["id"], time, flow["name"], status, flow["params"], jobs)

    def tree(self) -> Tree:
        """Generate a rich tree of the Flow"""
        tree = Tree(f"[bold underline]Flow {self.name}", highlight=True)
        tree.add(f"ID: {self.id}")
        tree.add(f"Submitted: {self.time.format()} ({self.time.humanize()})")
        tree.add(f"Status: {self.status.__rich__()}")
        ptree = tree.add("Parameters")
        for param, val in self.params.items():
            ptree.add(f"{param}: [cyan]{val}")
        jtree = tree.add("Jobs")
        for job in self.jobs:
            jtree.add(job.tree())
        return tree


@define
class APIInterface:
    """Interface to the eCTF API"""

    config: Config
    auth: HTTPBearerAuth = field(repr=False)

    @classmethod
    def from_config(cls) -> Self:
        """Create an APIInterface from the config file"""
        config = Config.load()
        return cls(config, HTTPBearerAuth(config.token))

    def _request(
        self,
        method: Callable,
        path: str,
        **kwargs,  # noqa: ANN003
    ) -> requests.Response:
        self.config.assert_configured()

        url = f"{self.config.api_url}/api/{path}/"
        debug(f"Sending {method.__name__} to {url}")
        r: requests.Response = method(url, auth=self.auth, **kwargs)

        debug(f"Server responded with {r.status_code}: {r.reason}")
        if r.ok:
            return r

        debug(f"Received error! Header: {r.request.headers}")

        raise APIError(r)

    def _get(self, path: str, **kwargs) -> requests.Response:  # noqa: ANN003
        return self._request(requests.get, path, **kwargs)

    def _post(self, path: str, **kwargs) -> requests.Response:  # noqa: ANN003
        return self._request(requests.post, path, **kwargs)

    def _patch(self, path: str, **kwargs) -> requests.Response:  # noqa: ANN003
        return self._request(requests.patch, path, **kwargs)

    def flow_list(self, flow: str, count: int) -> list[Flow]:
        """List the most recent tests

        :param flow: The name of the flow
        :param count: The number of tests to list
        """
        r = self._get(f"flow/{flow}", params={"num": str(count)})
        return [Flow.from_dict(test) for test in r.json()]

    def flow_info(self, flow: str, test_id: str) -> Flow:
        """Get the details of a specific test

        :param test_id: ID of the target test flow
        """
        r = self._get(f"flow/{flow}/{test_id}")
        return Flow.from_dict(r.json())

    def flow_submit(self, flow: str, body: dict | tuple) -> str:
        """Submit a commit to be tested

        :param flow: Name of flow
        :param body: Body of the request
        :return: Test flow ID of the new job
        """
        r = self._post(f"flow/{flow}", json=body)
        return r.content.decode()

    def flow_cancel(self, flow: str, test_id: str) -> None:
        """Cancel a submitted test

        :param flow: Name of flow
        :param test_id: ID of the target test flow
        """
        self._post(f"flow/{flow}/{test_id}/cancel")

    def flow_pull(self, flow: str, job_id: str) -> Iterator[bytes]:
        """Pull the results of a completed job

        :param flow: Name of flow
        :param job_id: ID of the target job
        :return: A chunked iterator of the byte contents of the completed job
        """
        r = self._get(f"flow/{flow}/job/{job_id}")
        yield from r.iter_content(chunk_size=2048)

    def flow_update(self, flow: str, job_id: str, args: dict) -> None:
        """Update the status of a pending job

        :param flow: Name of flow
        :param test_id: ID of the target flow
        :param job_id: ID of the target job
        :param args: Arbitrary JSON-able data to send
        """
        self._patch(f"flow/{flow}/{job_id}", json=args)

    def list_packages(self) -> list[str]:
        """Get the list of available attack packages

        :return: Attack package names
        """
        r = self._get("package")
        return r.json()

    def get_package(self, package: str) -> Iterator[bytes]:
        """Download a specific attack package

        :return: A chunked iterator of the byte contents of the attack package
        """
        r = self._get(f"package/{package}")
        yield from r.iter_content(chunk_size=2048)

    def submit_flag(self, flag: str, contents: dict | tuple) -> str:
        """Submit a flag that requires arbitrary data

        :param flag: Name of flag
        :param contents: Data required by flag
        :return: Flag to submit to the scoreboard
        """
        r = self._post(f"flag/{flag}", json=contents)
        return r.content.decode()

    def submit_flag_file(self, flag: str, file: BytesIO) -> str:
        """Submit a flag that requires a file

        :param flag: Name of flag
        :param file: Byte file object to submit
        :return: Flag to submit to the scoreboard
        """
        r = self._post(f"flag/{flag}", files={flag: file})
        return r.content.decode()
