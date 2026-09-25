from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
import tempfile
import traceback
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from http.client import HTTPMessage
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

API_ROOT = "https://api.github.com"
MAX_ACTIVE_REPOSITORIES = 100
MAX_PAGES = 10
MAX_REQUESTS = 1_000
RATE_HEADROOM = 100
MAX_HTTP_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_RAW_WORKFLOW_BYTES = 1024 * 1024
# The largest repository in the estate carries about 15 workflow files; the
# bound exists so one pathological repository cannot consume the run.
MAX_WORKFLOWS_PER_REPOSITORY = 50
HTTP_READ_CHUNK_BYTES = 64 * 1024
WORKFLOW_PREFIX = ".github/workflows/"
AUDIT_WORKFLOW_PATH = WORKFLOW_PREFIX + "portfolio-audit.yml"

POLICY_KEYS = {
    "schema_version",
    "owner",
    "expected_repositories",
    "baseline_exemptions",
    "dependabot_max_age_days",
    "release_policy_pins",
}
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
WORKFLOW_FAMILY_RE = re.compile(r"^[A-Za-z0-9._-]+\.ya?ml$")
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_PREFIX_RE = re.compile(r"(?:[a-z0-9]+(?:-[a-z0-9]+)*/)?v")
VERSION_SUFFIX_RE = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
PR_EVENTS = frozenset({"pull_request", "pull_request_target", "merge_group"})
ALLOWED_CONCLUSIONS = frozenset(
    {
        "success",
        "failure",
        "timed_out",
        "action_required",
        "startup_failure",
        "stale",
        "cancelled",
        "skipped",
        "neutral",
    }
)
FAILED_CONCLUSIONS = frozenset(
    {"failure", "timed_out", "action_required", "startup_failure", "stale"}
)
NOTICE_CONCLUSIONS = frozenset({"cancelled", "skipped", "neutral"})
RELEASE_POLICY_PATH = "ryanduguid/release-policy/.github/workflows/"
RELEASE_POLICY_USES_LINE_RE = re.compile(
    r"^\s*(?:-\s*)?uses\s*:\s*(?P<value>.*?)\s*$",
    re.IGNORECASE,
)
RELEASE_POLICY_VALUE_RE = re.compile(
    r"^(?P<quote>[\"']?)"
    r"ryanduguid/release-policy/\.github/workflows/"
    r"(?P<family>[A-Za-z0-9._-]+\.ya?ml)@"
    r"(?P<pin>[^\s\"'#]+)(?P=quote)(?:[ \t]+#.*)?[ \t]*$",
    re.IGNORECASE,
)
# `gh attestation verify --signer-workflow <path>` names the workflow whose
# identity signed an attestation. It is not a workflow reference: it carries no
# `@<sha>`, and the commit is pinned by the separate `--signer-digest`.
SIGNER_WORKFLOW_RE = re.compile(
    r"ryanduguid/release-policy/\.github/workflows/[A-Za-z0-9._-]+\.ya?ml"
)
# Recognise a literal commit or a shell variable. This static check cannot
# establish the variable's value at runtime.
SIGNER_DIGEST_RE = re.compile(
    r"(?:[0-9a-f]{40}|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\}))"
)


class PolicyError(ValueError):
    pass


class ApiError(RuntimeError):
    pass


class AuthenticationError(ApiError):
    pass


class AuthorisationError(ApiError):
    pass


class RateLimitError(ApiError):
    pass


class ResponseError(ApiError):
    pass


class SafetyLimitError(ApiError):
    pass


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "headers",
            {str(key).casefold(): str(value) for key, value in self.headers.items()},
        )


class HttpTransport(Protocol):
    def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
        pass


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: HTTPMessage,
        new_url: str,
    ) -> urllib.request.Request | None:
        destination = urllib.parse.urlparse(
            urllib.parse.urljoin(request.full_url, new_url)
        )
        source = urllib.parse.urlparse(request.full_url)
        try:
            source_port = source.port
            destination_port = destination.port
        except ValueError:
            raise ResponseError("cross-origin redirect was rejected") from None
        if (
            source.scheme != "https"
            or destination.scheme != "https"
            or source.hostname != destination.hostname
            or source_port != destination_port
        ):
            raise ResponseError("cross-origin redirect was rejected")
        return super().redirect_request(
            request, file_pointer, code, message, headers, destination.geturl()
        )


class UrllibTransport:
    def __init__(
        self,
        *,
        opener: Any | None = None,
        max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES,
    ) -> None:
        if (
            type(max_response_bytes) is not int
            or not 0 < max_response_bytes <= MAX_HTTP_RESPONSE_BYTES
        ):
            raise ValueError(
                f"maximum response bytes must be between 1 and {MAX_HTTP_RESPONSE_BYTES}"
            )
        self._opener = opener or urllib.request.build_opener(SameOriginRedirectHandler())
        self._max_response_bytes = max_response_bytes

    def _read_body(self, response: Any) -> bytes:
        body = bytearray()
        while len(body) <= self._max_response_bytes:
            remaining = self._max_response_bytes + 1 - len(body)
            chunk = response.read(min(HTTP_READ_CHUNK_BYTES, remaining))
            if not isinstance(chunk, bytes):
                raise ResponseError("HTTP response body was invalid")
            if not chunk:
                break
            body.extend(chunk)
        if len(body) > self._max_response_bytes:
            raise ResponseError("HTTP response exceeded the size limit")
        return bytes(body)

    def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self._opener.open(request, timeout=30) as response:
                return HttpResponse(
                    response.status,
                    dict(response.headers.items()),
                    self._read_body(response),
                )
        except urllib.error.HTTPError as error:
            response_headers = dict(error.headers.items()) if error.headers is not None else {}
            return HttpResponse(error.code, response_headers, self._read_body(error))
        except urllib.error.URLError:
            raise ResponseError("network request failed") from None


def _is_repository_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and value not in {".", ".."}
        and REPOSITORY_RE.fullmatch(value) is not None
    )


class AuditStatus(StrEnum):
    ALL_CLEAR = "ALL_CLEAR"
    ACTION_REQUIRED = "ACTION_REQUIRED"
    INCOMPLETE = "INCOMPLETE"


class Severity(StrEnum):
    ACTION = "ACTION"
    NOTICE = "NOTICE"


SEVERITY_ORDER = {Severity.ACTION: 0, Severity.NOTICE: 1}


@dataclass(frozen=True)
class Policy:
    schema_version: int
    owner: str
    expected_repositories: tuple[str, ...]
    workflow_exemptions: dict[str, str]
    dependabot_exemptions: dict[str, str]
    dependabot_max_age_days: int
    release_policy_pins: dict[str, frozenset[str]]
    tagged_release_workflows: dict[str, dict[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    severity: Severity
    repository: str
    code: str
    summary: str
    url: str


@dataclass(frozen=True)
class CollectionProblem:
    code: str
    repository: str | None
    summary: str


@dataclass(frozen=True)
class WorkflowRun:
    run_id: int
    path: str
    conclusion: str
    created_at: datetime = datetime.min.replace(tzinfo=UTC)
    audit_enforcement_only: bool = False


@dataclass(frozen=True)
class DependabotPullRequest:
    number: int
    created_at: datetime


@dataclass(frozen=True)
class RepositorySnapshot:
    name: str
    default_branch: str
    paths: frozenset[str]
    workflow_sources: dict[str, str]
    workflow_runs: tuple[WorkflowRun, ...]
    dependabot_pull_requests: tuple[DependabotPullRequest, ...]


@dataclass(frozen=True)
class CollectionResult:
    discovered_repositories: tuple[str, ...]
    repositories: tuple[RepositorySnapshot, ...]
    problems: tuple[CollectionProblem, ...]
    request_count: int
    rate_limit: dict[str, str]


@dataclass(frozen=True)
class AuditReport:
    schema_version: int
    owner: str
    started_at: datetime
    finished_at: datetime
    repository_count: int
    request_count: int
    rate_limit: dict[str, str]
    status: AuditStatus
    findings: tuple[Finding, ...]
    collection_errors: tuple[CollectionProblem, ...]


def _require_exact_keys(raw: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - raw.keys()
    extra = raw.keys() - expected
    if missing:
        raise PolicyError(f"missing {label} keys: {', '.join(sorted(missing))}")
    if extra:
        raise PolicyError(f"unexpected {label} keys: {', '.join(sorted(extra))}")


def _require_exemptions(raw: object, repositories: set[str]) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(raw, dict):
        raise PolicyError("baseline exemptions must be an object")
    _require_exact_keys(raw, {"workflow", "dependabot"}, "baseline exemption")

    exemptions: list[dict[str, str]] = []
    for family in ("workflow", "dependabot"):
        values = raw[family]
        if not isinstance(values, dict):
            raise PolicyError(f"{family} exemption map must be an object")
        validated: dict[str, str] = {}
        for repository, reason in values.items():
            if repository not in repositories or not isinstance(reason, str) or not reason.strip():
                raise PolicyError("exemption must name a known repository and have a reason")
            validated[repository] = reason.strip()
        exemptions.append(validated)
    return exemptions[0], exemptions[1]


def _require_release_policy_pins(raw: object) -> dict[str, frozenset[str]]:
    if not isinstance(raw, dict) or not raw:
        raise PolicyError("release policy pins must be a non-empty object")
    pins: dict[str, frozenset[str]] = {}
    for workflow, values in raw.items():
        if not isinstance(workflow, str) or WORKFLOW_FAMILY_RE.fullmatch(workflow) is None:
            raise PolicyError("release policy workflow family must be non-empty and end in .yml or .yaml")
        if not isinstance(values, list) or not values:
            raise PolicyError("release policy pins must be non-empty lists")
        if not all(isinstance(value, str) and FULL_SHA_RE.fullmatch(value) for value in values):
            raise PolicyError("release policy pins must be 40 lowercase hexadecimal SHAs")
        if len(set(values)) != len(values):
            raise PolicyError("release policy pins must be unique")
        pins[workflow] = frozenset(values)
    return pins


def _require_tagged_release_workflows(
    raw: object, repositories: set[str],
) -> dict[str, dict[str, str]]:
    if not isinstance(raw, dict):
        raise PolicyError("tagged release workflows must be an object")
    for repository, workflows in raw.items():
        if repository not in repositories or not isinstance(workflows, dict) or not workflows:
            raise PolicyError("tagged release workflows must name a known repository and workflows")
        for workflow, prefix in workflows.items():
            if (
                WORKFLOW_FAMILY_RE.fullmatch(workflow) is None
                or not isinstance(prefix, str)
                or TAG_PREFIX_RE.fullmatch(prefix) is None
            ):
                raise PolicyError("tagged release workflow needs a filename and v or component/v prefix")
    return raw


def load_policy(path: Path) -> Policy:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError("policy must be valid UTF-8 JSON") from error
    if not isinstance(raw, dict):
        raise PolicyError("policy must be an object")
    optional_keys = {"tagged_release_workflows"} & raw.keys()
    _require_exact_keys(raw, POLICY_KEYS | optional_keys, "policy")

    if (
        not isinstance(raw["schema_version"], int)
        or isinstance(raw["schema_version"], bool)
        or raw["schema_version"] != 1
    ):
        raise PolicyError("policy schema version must be 1")
    if raw["owner"] != "ryanduguid":
        raise PolicyError("policy owner must be ryanduguid")

    repositories = raw["expected_repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise PolicyError("expected repositories must be a non-empty list")
    if not all(_is_repository_name(repository) for repository in repositories):
        raise PolicyError("repository name is invalid")
    if repositories != sorted(repositories, key=str.casefold) or len({repository.casefold() for repository in repositories}) != len(repositories):
        raise PolicyError("expected repositories must be sorted unique repository names")

    repository_set = set(repositories)
    workflow_exemptions, dependabot_exemptions = _require_exemptions(
        raw["baseline_exemptions"], repository_set
    )

    threshold = raw["dependabot_max_age_days"]
    if (
        not isinstance(threshold, int)
        or isinstance(threshold, bool)
        or threshold <= 0
        or threshold > timedelta.max.days
    ):
        raise PolicyError("dependabot maximum age must be a positive integer")

    return Policy(
        schema_version=raw["schema_version"],
        owner=raw["owner"],
        expected_repositories=tuple(repositories),
        workflow_exemptions=workflow_exemptions,
        dependabot_exemptions=dependabot_exemptions,
        dependabot_max_age_days=threshold,
        release_policy_pins=_require_release_policy_pins(raw["release_policy_pins"]),
        tagged_release_workflows=_require_tagged_release_workflows(
            raw.get("tagged_release_workflows", {}), repository_set,
        ),
    )


def _zulu(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def report_to_dict(report: AuditReport) -> dict[str, Any]:
    return {
        "schema_version": report.schema_version,
        "owner": report.owner,
        "started_at": _zulu(report.started_at),
        "finished_at": _zulu(report.finished_at),
        "repository_count": report.repository_count,
        "request_count": report.request_count,
        "rate_limit": dict(sorted(report.rate_limit.items())),
        "status": report.status.value,
        "findings": [
            {
                "severity": finding.severity.value,
                "repository": finding.repository,
                "code": finding.code,
                "summary": finding.summary,
                "url": finding.url,
            }
            for finding in report.findings
        ],
        "collection_errors": [asdict(error) for error in report.collection_errors],
    }


NEXT_LINK_RE = re.compile(r'<(?P<url>[^>]+)>;\s*rel="next"')


def _next_link(value: str) -> str | None:
    for part in value.split(","):
        match = NEXT_LINK_RE.search(part)
        if match:
            parsed = urllib.parse.urlparse(match.group("url"))
            if parsed.scheme != "https" or parsed.netloc != "api.github.com":
                raise ResponseError("pagination next link left api.github.com")
            return match.group("url")
    return None


def _decode_json(body: bytes) -> Any:
    def reject_non_standard_constant(value: str) -> None:
        raise ValueError(value)

    try:
        return json.loads(
            body.decode("utf-8"), parse_constant=reject_non_standard_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ResponseError("GitHub API response was not valid UTF-8 JSON") from None


class GitHubClient:
    def __init__(
        self,
        token: str,
        *,
        transport: HttpTransport | None = None,
        max_pages: int = MAX_PAGES,
        max_requests: int = MAX_REQUESTS,
        rate_headroom: int = RATE_HEADROOM,
    ) -> None:
        if not isinstance(token, str) or not token.strip():
            raise AuthenticationError("installation token must not be blank")
        if (
            not isinstance(max_pages, int)
            or isinstance(max_pages, bool)
            or not 0 < max_pages <= MAX_PAGES
        ):
            raise ValueError(f"maximum pages must be between 1 and {MAX_PAGES}")
        if (
            not isinstance(max_requests, int)
            or isinstance(max_requests, bool)
            or not 0 < max_requests <= MAX_REQUESTS
        ):
            raise ValueError(f"maximum requests must be between 1 and {MAX_REQUESTS}")
        if (
            not isinstance(rate_headroom, int)
            or isinstance(rate_headroom, bool)
            or rate_headroom < RATE_HEADROOM
        ):
            raise ValueError(f"rate headroom must be at least {RATE_HEADROOM}")

        self._token = token
        self._transport = transport or UrllibTransport()
        self._max_pages = max_pages
        self._max_requests = max_requests
        self._rate_headroom = rate_headroom
        self._last_link = ""
        self.request_count = 0
        self.rate_limit: dict[str, str] = {}

    def _api_url(
        self,
        path: str,
        query: Mapping[str, object] | Sequence[tuple[str, object]] | None,
    ) -> str:
        if not isinstance(path, str):
            raise ResponseError("API path was invalid")
        if path.startswith("/"):
            url = f"{API_ROOT}{path}"
        else:
            parsed = urllib.parse.urlparse(path)
            if parsed.scheme != "https" or parsed.netloc != "api.github.com":
                raise ResponseError("API request left api.github.com")
            url = path

        if query is None:
            return url
        try:
            encoded = urllib.parse.urlencode(query, doseq=True)
        except (TypeError, ValueError):
            raise ResponseError("API query parameters were invalid") from None
        if not encoded:
            return url
        parsed_url = urllib.parse.urlsplit(url)
        query_string = "&".join(filter(None, (parsed_url.query, encoded)))
        return urllib.parse.urlunsplit(parsed_url._replace(query=query_string))

    def _require_request_headroom(self) -> None:
        if self.rate_limit and int(self.rate_limit["remaining"]) <= self._rate_headroom:
            raise RateLimitError(
                f"rate limit does not preserve {self._rate_headroom}-request headroom"
            )

    def _begin_rest_request(self) -> None:
        self._require_request_headroom()
        if self.request_count >= self._max_requests:
            raise SafetyLimitError("REST request ceiling was reached")
        self.request_count += 1

    @staticmethod
    def _rate_value(headers: Mapping[str, str], name: str) -> tuple[str, int]:
        value = headers.get(name)
        if value is None:
            raise RateLimitError("missing rate-limit headers")
        if not value.isdecimal():
            raise RateLimitError("invalid rate-limit headers")
        try:
            return value, int(value)
        except ValueError:
            raise RateLimitError("invalid rate-limit headers") from None

    def _record_rate_limit(self, headers: Mapping[str, str]) -> None:
        limit, _ = self._rate_value(headers, "x-ratelimit-limit")
        remaining, remaining_value = self._rate_value(
            headers, "x-ratelimit-remaining"
        )
        reset, _ = self._rate_value(headers, "x-ratelimit-reset")
        self.rate_limit = {"limit": limit, "remaining": remaining, "reset": reset}
        if remaining_value < self._rate_headroom:
            raise RateLimitError(
                f"rate limit fell below {self._rate_headroom}-request headroom"
            )

    @staticmethod
    def _is_rate_limited(response: HttpResponse) -> bool:
        if response.status == 429:
            return True
        if response.status != 403:
            return False
        if response.headers.get("retry-after") is not None:
            return True
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining is not None and remaining.isdecimal():
            try:
                if int(remaining) == 0:
                    return True
            except ValueError:
                raise RateLimitError("invalid rate-limit headers") from None
        try:
            body = _decode_json(response.body)
        except ResponseError:
            return False
        return (
            isinstance(body, dict)
            and isinstance(body.get("message"), str)
            and "rate limit" in body["message"].casefold()
        )

    def _send(self, url: str, headers: dict[str, str]) -> HttpResponse:
        try:
            return self._transport.request(url, headers)
        except Exception:
            raise ResponseError("HTTP request failed") from None

    def get_json(
        self,
        path: str,
        query: Mapping[str, object] | Sequence[tuple[str, object]] | None = None,
    ) -> Any:
        url = self._api_url(path, query)
        self._begin_rest_request()
        response = self._send(
            url,
            {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "ryanduguid-portfolio-audit",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if response.status == 401:
            raise AuthenticationError("GitHub installation authentication failed")
        if self._is_rate_limited(response):
            raise RateLimitError("GitHub API rate limit was reached")
        if response.status == 403:
            raise AuthorisationError("GitHub installation was not authorised for this resource")
        if not 200 <= response.status < 300:
            raise ResponseError("GitHub API returned an unexpected response")

        self._last_link = response.headers.get("link", "")
        self._record_rate_limit(response.headers)
        return _decode_json(response.body)

    def paginate(
        self,
        path: str,
        query: Mapping[str, object] | Sequence[tuple[str, object]] | None = None,
    ) -> tuple[dict[str, Any], ...]:
        items: list[dict[str, Any]] = []
        next_page: str | None = path
        page_count = 0
        next_query = query
        while next_page is not None:
            if page_count >= self._max_pages:
                raise SafetyLimitError(f"pagination exceeded {self._max_pages} pages")
            page = self.get_json(next_page, next_query)
            next_query = None
            page_count += 1
            if not isinstance(page, list):
                raise ResponseError("pagination page was not a list")
            if not all(isinstance(item, dict) for item in page):
                raise ResponseError("pagination page contained a non-object")
            items.extend(page)
            next_page = _next_link(self._last_link)
        return tuple(items)

    def require_capacity(self, required: int) -> None:
        if not isinstance(required, int) or isinstance(required, bool) or required < 0:
            raise ValueError("required capacity must be a non-negative integer")
        if not self.rate_limit:
            raise RateLimitError("rate-limit capacity has not been observed")
        if int(self.rate_limit["remaining"]) < required + self._rate_headroom:
            raise RateLimitError(
                f"rate limit does not preserve {self._rate_headroom}-request headroom"
            )

    def get_raw_bytes(self, url: str) -> bytes:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com":
            raise ResponseError("raw request left raw.githubusercontent.com")
        # A raw workflow fetch spends the same budget a REST call does: it
        # counts toward the request ceiling and the rate-limit headroom, so
        # the per-repository workflow loop cannot spend requests the ceiling
        # never sees.
        self._begin_rest_request()
        response = self._send(
            url,
            {"User-Agent": "ryanduguid-portfolio-audit"},
        )
        if not 200 <= response.status < 300:
            raise ResponseError("raw GitHub response was unsuccessful")
        if len(response.body) > MAX_RAW_WORKFLOW_BYTES:
            raise ResponseError("workflow source exceeded the size limit")
        return response.body


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def _positive_integer(value: object, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ResponseError(f"{label} was not a positive integer")
    return value


def _normalise_repository_name(value: object) -> str:
    if not _is_repository_name(value):
        raise ResponseError("repository name was invalid")
    assert isinstance(value, str)
    return value


def _normalise_default_branch(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ResponseError("default branch was invalid")
    if (
        any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(character.isspace() for character in value)
        or any(character in "~^:?*[" for character in value)
        or "\\" in value
        or ".." in value
        or "@{" in value
        or "//" in value
        or value.startswith("/")
        or value == "@"
        or any(part.startswith(".") for part in value.split("/"))
        or value.endswith(("/", ".", ".lock"))
    ):
        raise ResponseError("default branch was invalid")
    return value


def _normalise_workflow_path(value: object) -> str:
    if not isinstance(value, str):
        raise ResponseError("workflow path was not a string")
    parts = value.split("/")
    if (
        not value.startswith(".github/workflows/")
        or len(parts) != 3
        or any(part in {"", ".", ".."} for part in parts)
        or "\\" in value
        or not value.lower().endswith((".yml", ".yaml"))
    ):
        raise ResponseError("workflow path was invalid")
    return value


def _normalise_tree_path(value: object) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ResponseError("tree path was invalid")
    if (
        "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ResponseError("tree path was invalid")
    return value


def _quote_component(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _quote_workflow_path(value: str) -> str:
    return "/".join(_quote_component(part) for part in PurePosixPath(value).parts)


def _normalise_run(raw: Mapping[str, Any]) -> WorkflowRun:
    run_id = _positive_integer(raw.get("id"), "workflow run id")
    path = _normalise_workflow_path(raw.get("path"))
    conclusion = raw.get("conclusion")
    if not isinstance(conclusion, str) or conclusion not in ALLOWED_CONCLUSIONS:
        raise ResponseError("workflow run omitted required fields")
    if raw.get("status") != "completed":
        raise ResponseError("workflow run was not completed")
    return WorkflowRun(run_id, path, conclusion, _parse_github_time(raw.get("created_at")))


def _run_event(raw: Mapping[str, Any]) -> str:
    event = raw.get("event")
    if not isinstance(event, str) or re.fullmatch(r"[a-z_]+", event) is None:
        raise ResponseError("workflow run event was invalid")
    return event


def _run_order(run: WorkflowRun) -> tuple[datetime, int]:
    # Creation time keeps an old rerun from replacing a newer release attempt.
    return run.created_at, run.run_id


def _parse_github_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise ResponseError("GitHub timestamp was not a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ResponseError("GitHub timestamp was malformed") from error
    if parsed.tzinfo is None:
        raise ResponseError("GitHub timestamp lacked a timezone")
    return parsed.astimezone(UTC)


PROBLEM_SUMMARIES = {
    "GITHUB_AUTHENTICATION_FAILED": "GitHub authentication failed",
    "GITHUB_AUTHORISATION_FAILED": "GitHub authorisation failed",
    "GITHUB_RATE_LIMITED": "GitHub rate limit prevented complete collection",
    "GITHUB_RESPONSE_INVALID": "GitHub returned invalid public metadata",
    "REQUEST_SAFETY_LIMIT": "request safety limit prevented complete collection",
    "ESTATE_LIMIT_EXCEEDED": "active public repository limit was exceeded",
    "REPOSITORY_ACCESS_DENIED": "repository access was denied",
    "TREE_TRUNCATED": "repository tree was truncated",
    "WORKFLOW_COUNT_EXCEEDED": "repository carries more workflow files than the per-repository bound",
    "RAW_WORKFLOW_REQUEST_FAILED": "workflow source request failed",
    "RAW_WORKFLOW_MISMATCH": "workflow source did not match its Git blob identity",
    "RAW_WORKFLOW_INVALID_UTF8": "workflow source was not valid UTF-8",
}


def _problem(code: str, repository: str | None = None) -> CollectionProblem:
    return CollectionProblem(code, repository, PROBLEM_SUMMARIES[code])


def _result(
    client: GitHubClient,
    discovered: Sequence[str] = (),
    repositories: Sequence[RepositorySnapshot] = (),
    problems: Sequence[CollectionProblem] = (),
) -> CollectionResult:
    return CollectionResult(
        tuple(discovered),
        tuple(repositories),
        tuple(problems),
        client.request_count,
        dict(client.rate_limit),
    )


def _normalise_repository(raw: Mapping[str, Any]) -> tuple[str, str, bool]:
    name = _normalise_repository_name(raw.get("name"))
    default_branch = _normalise_default_branch(raw.get("default_branch"))
    flags: list[bool] = []
    for flag_name in ("private", "fork", "archived"):
        value = raw.get(flag_name)
        if type(value) is not bool:
            raise ResponseError("repository visibility fields were invalid")
        flags.append(value)
    active = not any(flags)
    return name, default_branch, active


def _normalise_tree(
    raw: object,
) -> tuple[frozenset[str], tuple[tuple[str, str], ...], bool]:
    if not isinstance(raw, dict):
        raise ResponseError("Git tree response was not an object")
    truncated = raw.get("truncated")
    tree = raw.get("tree")
    if type(truncated) is not bool or not isinstance(tree, list):
        raise ResponseError("Git tree response omitted required fields")

    paths: set[str] = set()
    workflows: list[tuple[str, str]] = []
    for entry in tree:
        if not isinstance(entry, dict):
            raise ResponseError("Git tree entry was not an object")
        path = _normalise_tree_path(entry.get("path"))
        entry_type = entry.get("type")
        if not isinstance(entry_type, str) or entry_type not in {
            "blob",
            "tree",
            "commit",
        }:
            raise ResponseError("Git tree entry type was invalid")
        if entry_type == "blob":
            paths.add(path)
        if (
            path.startswith(".github/workflows/")
            and path.lower().endswith((".yml", ".yaml"))
            and len(path.split("/")) == 3
        ):
            workflow_path = _normalise_workflow_path(path)
            sha = entry.get("sha")
            if (
                entry_type != "blob"
                or not isinstance(sha, str)
                or FULL_SHA_RE.fullmatch(sha) is None
            ):
                raise ResponseError("workflow Git blob identity was invalid")
            workflows.append((workflow_path, sha))
    workflows.sort(key=lambda item: item[0].casefold())
    return frozenset(paths), tuple(workflows), truncated


def _normalise_runs(
    raw: object, *, default_branch: str | None = None,
) -> tuple[WorkflowRun, ...]:
    if not isinstance(raw, dict) or not isinstance(raw.get("workflow_runs"), list):
        raise ResponseError("workflow runs response omitted required fields")
    runs = raw["workflow_runs"]
    if not all(isinstance(item, dict) for item in runs):
        raise ResponseError("workflow runs response contained a non-object")
    normalised = []
    for item in runs:
        if isinstance(item.get("path"), str) and item["path"].startswith("dynamic/"):
            continue
        run = _normalise_run(item)
        if default_branch is not None:
            if _run_event(item) in PR_EVENTS:
                continue
            if _normalise_default_branch(item.get("head_branch")) != default_branch:
                continue
        normalised.append(run)
    return tuple(sorted(normalised, key=_run_order, reverse=True))


def _audit_enforcement_only(raw: object, run_id: int) -> bool:
    """Keep prior audit results separate from audit infrastructure failures."""
    if (
        not isinstance(raw, dict)
        or type(raw.get("total_count")) is not int
        or not isinstance(raw.get("jobs"), list)
        or not all(isinstance(job, dict) for job in raw["jobs"])
    ):
        raise ResponseError("audit jobs response omitted required fields")
    jobs = raw["jobs"]
    expected = {
        "invocation_guard": {"success"}, "collect": {"success"},
        "deliver": {"success", "skipped"}, "enforce": {"failure"},
    }
    # Any missing, additional or renamed job retains the failed-run finding.
    if raw["total_count"] != len(expected) or len(jobs) != len(expected):
        return False
    seen = set()
    for job in jobs:
        name = job.get("name")
        if (
            not isinstance(name, str) or name not in expected or name in seen
            or job.get("run_id") != run_id or job.get("status") != "completed"
            or not isinstance(job.get("conclusion"), str)
            or job.get("conclusion") not in expected[name]
        ):
            return False
        seen.add(name)
        if name == "enforce":
            steps = job.get("steps")
            if not isinstance(steps, list) or not steps:
                return False
            failed_steps = []
            for step in steps:
                if (
                    not isinstance(step, dict) or step.get("status") != "completed"
                    or not isinstance(step.get("conclusion"), str)
                    or step.get("conclusion") not in {"success", "failure"}
                ):
                    return False
                if step["conclusion"] == "failure":
                    failed_steps.append(step.get("name"))
            if failed_steps != ["Enforce report and requested delivery"]:
                return False
    return True


def _collect_tagged_release_run(
    repository_path: str, workflow: str, prefix: str, client: GitHubClient,
) -> WorkflowRun | None:
    raw = client.get_json(
        f"{repository_path}/actions/workflows/{_quote_component(workflow)}/runs",
        {"status": "completed", "per_page": 100},
    )
    # Validate the complete bounded response before considering any success.
    _normalise_runs(raw)
    candidates: list[tuple[WorkflowRun, str, str]] = []
    for item in raw["workflow_runs"]:
        run = _normalise_run(item)
        if run.path != WORKFLOW_PREFIX + workflow:
            raise ResponseError("tagged release run belonged to another workflow")
        if _run_event(item) not in {"push", "release", "workflow_dispatch"}:
            continue
        branch = _normalise_default_branch(item.get("head_branch"))
        if re.fullmatch(re.escape(prefix) + VERSION_SUFFIX_RE, branch) is None:
            continue
        head_repository = item.get("head_repository")
        sha = item.get("head_sha")
        if (
            not isinstance(head_repository, dict)
            or head_repository.get("full_name") != repository_path.removeprefix("/repos/")
            or not isinstance(sha, str)
            or FULL_SHA_RE.fullmatch(sha) is None
        ):
            raise ResponseError("tagged release source identity was invalid")
        candidates.append((run, branch, sha))
    if not candidates:
        return None
    run, tag, sha = max(candidates, key=lambda item: _run_order(item[0]))

    # The tags endpoint supplies the peeled commit for both annotated and
    # lightweight tags. A missing or moved latest tag must not fall back to green.
    tags = client.paginate(f"{repository_path}/tags", {"per_page": 100})
    matches = []
    for item in tags:
        name = _normalise_default_branch(item.get("name"))
        commit = item.get("commit")
        if not isinstance(commit, dict) or not isinstance(commit.get("sha"), str) or FULL_SHA_RE.fullmatch(commit["sha"]) is None:
            raise ResponseError("release tag commit was invalid")
        if name == tag:
            matches.append(commit["sha"])
    if matches != [sha]:
        raise ResponseError("latest release run did not match its current tag commit")
    heads = client.get_json(f"{repository_path}/git/matching-refs/heads/{_quote_component(tag)}")
    if not isinstance(heads, list):
        raise ResponseError("release branch disambiguation was invalid")
    for head in heads:
        ref = head.get("ref") if isinstance(head, dict) else None
        if not isinstance(ref, str) or not ref.startswith("refs/heads/"):
            raise ResponseError("release branch disambiguation was invalid")
        if ref == f"refs/heads/{tag}":
            raise ResponseError("release run ref was ambiguous between branch and tag")
    return run


def _normalise_dependabot_pull_requests(
    raw: Sequence[Mapping[str, Any]],
) -> tuple[DependabotPullRequest, ...]:
    pull_requests: list[DependabotPullRequest] = []
    for item in raw:
        user = item.get("user")
        if not isinstance(user, dict) or not isinstance(user.get("login"), str):
            raise ResponseError("pull request author fields were invalid")
        if user["login"] != "dependabot[bot]":
            continue
        pull_requests.append(
            DependabotPullRequest(
                _positive_integer(item.get("number"), "pull request number"),
                _parse_github_time(item.get("created_at")),
            )
        )
    return tuple(pull_requests)


def _collect_repository(
    owner: str,
    name: str,
    default_branch: str,
    client: GitHubClient,
    problems: list[CollectionProblem],
    tagged_release_workflows: Mapping[str, str],
) -> RepositorySnapshot:
    owner_component = _quote_component(owner)
    repository_component = _quote_component(name)
    branch_component = _quote_component(default_branch)
    repository_path = f"/repos/{owner_component}/{repository_component}"

    tree_response = client.get_json(
        f"{repository_path}/git/trees/{branch_component}", {"recursive": 1}
    )
    paths, workflow_blobs, truncated = _normalise_tree(tree_response)
    if truncated:
        problems.append(_problem("TREE_TRUNCATED", name))

    workflow_sources: dict[str, str] = {}
    # One repository carrying an unusual number of workflow files must not
    # consume the run's request budget before the ceiling trips, so the
    # count is bounded per repository and the fetch loop is skipped when the
    # bound is exceeded. The global REST ceiling still covers every raw
    # fetch, because get_raw_bytes routes through _begin_rest_request.
    if len(workflow_blobs) > MAX_WORKFLOWS_PER_REPOSITORY:
        problems.append(_problem("WORKFLOW_COUNT_EXCEEDED", name))
    else:
        for workflow_path, expected_sha in workflow_blobs:
            raw_url = (
                "https://raw.githubusercontent.com/"
                f"{owner_component}/{repository_component}/{branch_component}/"
                f"{_quote_workflow_path(workflow_path)}"
            )
            try:
                source_bytes = client.get_raw_bytes(raw_url)
            except ResponseError:
                problems.append(_problem("RAW_WORKFLOW_REQUEST_FAILED", name))
                continue
            if git_blob_sha(source_bytes) != expected_sha:
                problems.append(_problem("RAW_WORKFLOW_MISMATCH", name))
                continue
            try:
                workflow_sources[workflow_path] = source_bytes.decode("utf-8")
            except UnicodeDecodeError:
                problems.append(_problem("RAW_WORKFLOW_INVALID_UTF8", name))

    workflow_runs = _normalise_runs(
        client.get_json(
            f"{repository_path}/actions/runs",
            {"branch": default_branch, "status": "completed", "per_page": 100},
        ),
        default_branch=default_branch,
    )
    for workflow, prefix in tagged_release_workflows.items():
        if WORKFLOW_PREFIX + workflow not in workflow_sources:
            raise ResponseError("configured tagged release workflow was not collected")
        run = _collect_tagged_release_run(repository_path, workflow, prefix, client)
        if run is not None:
            workflow_runs += (run,)
    workflow_runs = tuple(sorted(workflow_runs, key=_run_order, reverse=True))
    if name.casefold() == "portfolio-audit":
        run = next((item for item in workflow_runs if item.path == AUDIT_WORKFLOW_PATH), None)
        if run is not None and run.conclusion == "failure":
            enforcement_only = _audit_enforcement_only(
                client.get_json(
                    f"{repository_path}/actions/runs/{run.run_id}/jobs",
                    {"filter": "latest", "per_page": 100},
                ),
                run.run_id,
            )
            workflow_runs = tuple(
                replace(item, audit_enforcement_only=enforcement_only) if item is run else item
                for item in workflow_runs
            )
    dependabot_pull_requests = _normalise_dependabot_pull_requests(
        client.paginate(
            f"{repository_path}/pulls", {"state": "open", "per_page": 100}
        )
    )
    return RepositorySnapshot(
        name,
        default_branch,
        paths,
        workflow_sources,
        workflow_runs,
        dependabot_pull_requests,
    )


def collect_estate(policy: Policy, client: GitHubClient) -> CollectionResult:
    problems: list[CollectionProblem] = []
    owner = _quote_component(policy.owner)
    try:
        raw_repositories = client.paginate(
            f"/users/{owner}/repos", {"type": "owner", "per_page": 100}
        )
    except AuthenticationError:
        return _result(client, problems=[_problem("GITHUB_AUTHENTICATION_FAILED")])
    except AuthorisationError:
        return _result(client, problems=[_problem("GITHUB_AUTHORISATION_FAILED")])
    except RateLimitError:
        return _result(client, problems=[_problem("GITHUB_RATE_LIMITED")])
    except SafetyLimitError:
        return _result(client, problems=[_problem("REQUEST_SAFETY_LIMIT")])
    except ResponseError:
        return _result(client, problems=[_problem("GITHUB_RESPONSE_INVALID")])

    active_repositories: list[tuple[str, str]] = []
    for raw_repository in raw_repositories:
        try:
            name, default_branch, active = _normalise_repository(raw_repository)
        except ResponseError:
            problems.append(_problem("GITHUB_RESPONSE_INVALID"))
            continue
        if active:
            active_repositories.append((name, default_branch))
    active_repositories.sort(key=lambda item: item[0].casefold())
    discovered = tuple(item[0] for item in active_repositories)

    if len(active_repositories) > MAX_ACTIVE_REPOSITORIES:
        problems.append(_problem("ESTATE_LIMIT_EXCEEDED"))
        return _result(client, discovered, problems=problems)

    tagged_workflow_count = sum(
        len(policy.tagged_release_workflows.get(name, {}))
        for name, _default_branch in active_repositories
    )
    try:
        # Each tagged workflow adds a run query, bounded tag pagination and
        # a branch-disambiguation request; retain the existing rate headroom.
        client.require_capacity(
            len(active_repositories) * 3 + tagged_workflow_count * (MAX_PAGES + 2)
        )
    except RateLimitError:
        problems.append(_problem("GITHUB_RATE_LIMITED"))
        return _result(client, discovered, problems=problems)

    repositories: list[RepositorySnapshot] = []
    for name, default_branch in active_repositories:
        try:
            repositories.append(
                _collect_repository(
                    policy.owner, name, default_branch, client, problems,
                    policy.tagged_release_workflows.get(name, {}),
                )
            )
        except AuthenticationError:
            problems.append(_problem("GITHUB_AUTHENTICATION_FAILED"))
            break
        except RateLimitError:
            problems.append(_problem("GITHUB_RATE_LIMITED"))
            break
        except SafetyLimitError:
            problems.append(_problem("REQUEST_SAFETY_LIMIT"))
            break
        except AuthorisationError:
            problems.append(_problem("REPOSITORY_ACCESS_DENIED", name))
        except ResponseError:
            problems.append(_problem("GITHUB_RESPONSE_INVALID", name))

    return _result(client, discovered, repositories, problems)


def _release_policy_candidates(source: str) -> tuple[str, ...]:
    candidates: list[str] = []
    for line in source.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = RELEASE_POLICY_USES_LINE_RE.fullmatch(line)
        if (
            match
            and RELEASE_POLICY_PATH.casefold()
            in match.group("value").casefold()
        ):
            candidates.append(match.group("value"))
    return tuple(candidates)


def _shell_commands(source: str) -> tuple[tuple[str, ...], ...]:
    """Read standalone shell commands; leave compound syntax unconsumed."""
    commands: list[tuple[str, ...]] = []
    for line in re.sub(r"(?<!\\)\\\r?\n", "", source).splitlines():
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        try:
            tokens = list(lexer)
        except ValueError:
            # Unsupported or malformed shell text cannot consume an identity.
            continue
        if any(token and all(character in ";&|()<>" for character in token) for token in tokens):
            continue
        commands.append(tuple(tokens))
    return tuple(commands)


def _signer_identity_occurrences(source: str) -> int:
    """Count attestation signer identities that are pinned by a digest.

    A `--signer-workflow` argument asserts which workflow's identity signed an
    attestation. Requiring `@<sha>` on it would be wrong, because the commit is
    pinned by the separate `--signer-digest`. Only one identity and one digest
    in the same verification command are recognised. Repeated options can
    overwrite earlier values, so counting pairs would conceal unused identities.
    """
    recognised = 0
    for command in _shell_commands(source):
        if command[:2] == ("-", "run:"):
            command = command[2:]
        if command[:3] != ("gh", "attestation", "verify") or "--" in command:
            continue
        arguments: dict[str, list[str]] = {"--signer-workflow": [], "--signer-digest": []}
        for index, token in enumerate(command):
            option, separator, value = token.partition("=")
            if option in arguments:
                if not separator:
                    value = command[index + 1] if index + 1 < len(command) else ""
                arguments[option].append(value)
        identities = arguments["--signer-workflow"]
        digests = arguments["--signer-digest"]
        if (
            len(identities) == len(digests) == 1
            and SIGNER_WORKFLOW_RE.fullmatch(identities[0])
            and SIGNER_DIGEST_RE.fullmatch(digests[0])
        ):
            recognised += 1
    return recognised


def _has_unconsumed_release_policy_occurrence(
    source: str,
    candidates: Sequence[str],
) -> bool:
    release_policy_path = RELEASE_POLICY_PATH.casefold()
    occurrence_count = source.casefold().count(release_policy_path)
    recognised_count = len(candidates) + _signer_identity_occurrences(source)
    return occurrence_count != recognised_count


def _finding_sort_key(finding: Finding) -> tuple[int, str, str, str]:
    return (
        SEVERITY_ORDER[finding.severity],
        finding.repository.casefold(),
        finding.code,
        finding.url,
    )


def _problem_sort_key(
    problem: CollectionProblem,
) -> tuple[bool, str, str, str]:
    return (
        problem.repository is not None,
        (problem.repository or "").casefold(),
        problem.code,
        problem.summary,
    )


def _repository_url(owner: str, repository: str) -> str:
    return (
        f"https://github.com/{_quote_component(owner)}/"
        f"{_quote_component(repository)}"
    )


def _source_url(
    owner: str,
    repository: RepositorySnapshot,
    workflow_path: str,
) -> str:
    _normalise_default_branch(repository.default_branch)
    _normalise_workflow_path(workflow_path)
    return (
        f"{_repository_url(owner, repository.name)}/blob/"
        f"{_quote_component(repository.default_branch)}/"
        f"{_quote_workflow_path(workflow_path)}"
    )


def evaluate(
    policy: Policy,
    collection: CollectionResult,
    now: datetime,
) -> tuple[Finding, ...]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("evaluation time must be timezone-aware")

    findings: list[Finding] = []
    expected = {
        repository.casefold(): repository
        for repository in policy.expected_repositories
    }
    discovered = {
        repository.casefold(): repository
        for repository in collection.discovered_repositories
    }

    for key, repository_name in discovered.items():
        if key not in expected:
            findings.append(
                Finding(
                    Severity.ACTION,
                    repository_name,
                    "UNEXPECTED_REPOSITORY",
                    "active public repository was not present in policy",
                    _repository_url(policy.owner, repository_name),
                )
            )
    for key, repository_name in expected.items():
        if key not in discovered:
            findings.append(
                Finding(
                    Severity.ACTION,
                    repository_name,
                    "EXPECTED_REPOSITORY_MISSING",
                    "expected active public repository was not discovered",
                    _repository_url(policy.owner, repository_name),
                )
            )

    workflow_exemptions = {
        repository.casefold() for repository in policy.workflow_exemptions
    }
    dependabot_exemptions = {
        repository.casefold() for repository in policy.dependabot_exemptions
    }
    approved_pins = {
        family.casefold(): pins
        for family, pins in policy.release_policy_pins.items()
    }
    stale_threshold = timedelta(days=policy.dependabot_max_age_days)

    for repository in collection.repositories:
        if repository.name.casefold() not in discovered:
            continue
        repository_url = _repository_url(policy.owner, repository.name)
        workflow_paths = tuple(
            sorted(
                (
                    path
                    for path in repository.paths
                    if path.startswith(WORKFLOW_PREFIX)
                    and path.lower().endswith((".yml", ".yaml"))
                    and len(path.split("/")) == 3
                ),
                key=str.casefold,
            )
        )

        if (
            repository.name.casefold() not in workflow_exemptions
            and not workflow_paths
        ):
            findings.append(
                Finding(
                    Severity.ACTION,
                    repository.name,
                    "WORKFLOW_BASELINE_MISSING",
                    "no tracked workflow YAML file was found",
                    repository_url,
                )
            )
        if (
            repository.name.casefold() not in dependabot_exemptions
            and ".github/dependabot.yml" not in repository.paths
        ):
            findings.append(
                Finding(
                    Severity.ACTION,
                    repository.name,
                    "DEPENDABOT_BASELINE_MISSING",
                    "missing .github/dependabot.yml",
                    repository_url,
                )
            )

        for workflow_path in workflow_paths:
            run = next(
                (
                    item
                    for item in repository.workflow_runs
                    if item.path == workflow_path
                ),
                None,
            )
            source_url = _source_url(policy.owner, repository, workflow_path)
            if run is None:
                findings.append(
                    Finding(
                        Severity.NOTICE,
                        repository.name,
                        "WORKFLOW_NO_RECENT_RUN",
                        "workflow had no run in the latest 100 completed runs",
                        source_url,
                    )
                )
            elif run.conclusion in FAILED_CONCLUSIONS:
                _positive_integer(run.run_id, "workflow run id")
                findings.append(
                    Finding(
                        Severity.NOTICE if run.audit_enforcement_only else Severity.ACTION,
                        repository.name,
                        "AUDIT_ENFORCEMENT_FAILED" if run.audit_enforcement_only else "WORKFLOW_RUN_FAILED",
                        (
                            "previous audit failed only in enforcement; current findings are evaluated separately"
                            if run.audit_enforcement_only else "latest completed workflow run failed"
                        ),
                        f"{repository_url}/actions/runs/"
                        f"{_quote_component(str(run.run_id))}",
                    )
                )
            elif run.conclusion in NOTICE_CONCLUSIONS:
                _positive_integer(run.run_id, "workflow run id")
                findings.append(
                    Finding(
                        Severity.NOTICE,
                        repository.name,
                        "WORKFLOW_RUN_NOTICE",
                        "latest completed workflow run needs review",
                        f"{repository_url}/actions/runs/"
                        f"{_quote_component(str(run.run_id))}",
                    )
                )

        for pull_request in repository.dependabot_pull_requests:
            if now - pull_request.created_at > stale_threshold:
                _positive_integer(pull_request.number, "pull request number")
                findings.append(
                    Finding(
                        Severity.ACTION,
                        repository.name,
                        "DEPENDABOT_PR_STALE",
                        "Dependabot pull request exceeded the maximum age",
                        f"{repository_url}/pull/"
                        f"{_quote_component(str(pull_request.number))}",
                    )
                )

        if repository.name.casefold() == "release-policy":
            continue

        for workflow_path, source in sorted(
            repository.workflow_sources.items(), key=lambda item: item[0].casefold()
        ):
            source_url = _source_url(policy.owner, repository, workflow_path)
            candidates = _release_policy_candidates(source)
            malformed = _has_unconsumed_release_policy_occurrence(
                source, candidates
            )
            unapproved = False
            for candidate in candidates:
                match = RELEASE_POLICY_VALUE_RE.fullmatch(candidate)
                if match is None or FULL_SHA_RE.fullmatch(match.group("pin")) is None:
                    malformed = True
                    continue
                pins = approved_pins.get(match.group("family").casefold())
                if pins is None or match.group("pin") not in pins:
                    unapproved = True
            if malformed:
                findings.append(
                    Finding(
                        Severity.ACTION,
                        repository.name,
                        "RELEASE_POLICY_PIN_MALFORMED",
                        "release-policy reference did not use a full lowercase commit SHA",
                        source_url,
                    )
                )
            elif unapproved:
                findings.append(
                    Finding(
                        Severity.ACTION,
                        repository.name,
                        "RELEASE_POLICY_PIN_UNAPPROVED",
                        "release-policy commit SHA was not approved for its workflow family",
                        source_url,
                    )
                )

    return tuple(sorted(findings, key=_finding_sort_key))


def _require_aware_timestamp(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")


def build_report(
    policy: Policy,
    collection: CollectionResult,
    findings: tuple[Finding, ...],
    started_at: datetime,
    finished_at: datetime,
) -> AuditReport:
    _require_aware_timestamp(started_at, "started_at")
    _require_aware_timestamp(finished_at, "finished_at")
    if finished_at < started_at:
        raise ValueError("finished_at must not precede started_at")

    sorted_findings = tuple(sorted(findings, key=_finding_sort_key))
    if collection.problems:
        status = AuditStatus.INCOMPLETE
    elif any(finding.severity is Severity.ACTION for finding in sorted_findings):
        status = AuditStatus.ACTION_REQUIRED
    else:
        status = AuditStatus.ALL_CLEAR

    return AuditReport(
        schema_version=policy.schema_version,
        owner=policy.owner,
        started_at=started_at,
        finished_at=finished_at,
        repository_count=len(collection.repositories),
        request_count=collection.request_count,
        rate_limit=dict(sorted(collection.rate_limit.items())),
        status=status,
        findings=sorted_findings,
        collection_errors=tuple(sorted(collection.problems, key=_problem_sort_key)),
    )


def render_json(report: AuditReport) -> str:
    return json.dumps(report_to_dict(report), indent=2, sort_keys=True) + "\n"


def render_text(report: AuditReport) -> str:
    action_count = sum(
        finding.severity is Severity.ACTION for finding in report.findings
    )
    error_count = len(report.collection_errors)
    if report.status is AuditStatus.ALL_CLEAR:
        heading = "GitHub portfolio audit: ALL_CLEAR (0 action findings)"
    elif report.status is AuditStatus.ACTION_REQUIRED:
        heading = (
            f"GitHub portfolio audit: ACTION_REQUIRED "
            f"({action_count} action findings)"
        )
    else:
        heading = (
            f"GitHub portfolio audit: INCOMPLETE ({action_count} action findings, "
            f"{error_count} collection errors)"
        )

    lines = [
        heading,
        f"Started: {_zulu(report.started_at)}",
        f"Finished: {_zulu(report.finished_at)}",
        f"Repositories collected: {report.repository_count}",
        f"REST requests: {report.request_count}",
    ]
    lines.extend(
        f"Rate limit {name}: {value}"
        for name, value in sorted(report.rate_limit.items())
    )
    for finding in report.findings:
        lines.extend(
            (
                f"[{finding.severity.value}] {finding.repository} "
                f"{finding.code}: {finding.summary}",
                finding.url,
            )
        )
    lines.extend(
        f"[ERROR] {problem.repository or 'account'} {problem.code}: {problem.summary}"
        for problem in report.collection_errors
    )
    if report.status is AuditStatus.ALL_CLEAR:
        lines.append("No action is required.")
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, value: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output:
            temporary_path = Path(output.name)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def write_outputs(report: AuditReport, json_path: Path, text_path: Path) -> None:
    failure: OSError | ValueError | None = None
    for path, value in (
        (json_path, render_json(report)),
        (text_path, render_text(report)),
    ):
        try:
            _atomic_write(path, value)
        except (OSError, ValueError) as error:
            if failure is None:
                failure = error
    if failure is not None:
        raise failure


def _minimal_incomplete_report(
    started_at: datetime,
    finished_at: datetime,
    code: str,
    summary: str,
) -> AuditReport:
    return AuditReport(
        schema_version=1,
        owner="ryanduguid",
        started_at=started_at,
        finished_at=finished_at,
        repository_count=0,
        request_count=0,
        rate_limit={},
        status=AuditStatus.INCOMPLETE,
        findings=(),
        collection_errors=(CollectionProblem(code, None, summary),),
    )


def _parse_now(value: str) -> datetime:
    if not value.endswith("Z"):
        raise argparse.ArgumentTypeError("time must be an ISO-8601 UTC value ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise argparse.ArgumentTypeError(
            "time must be an ISO-8601 UTC value ending in Z"
        ) from None
    return parsed.astimezone(UTC)


def _finish_time(fixed_time: datetime | None) -> datetime:
    return fixed_time if fixed_time is not None else datetime.now(UTC)


def _write_cli_report(
    report: AuditReport,
    json_path: Path,
    text_path: Path,
) -> int:
    try:
        write_outputs(report, json_path, text_path)
    except (OSError, ValueError):
        return 2
    print(
        f"Portfolio audit {report.status.value}: wrote {json_path} and {text_path}"
    )
    return 0


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--text-output", type=Path, required=True)
    parser.add_argument("--now", type=_parse_now)
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        # argparse always exits with an integer status. Treat anything else as
        # the usage-error code rather than raising from the error handler.
        return error.code if isinstance(error.code, int) else 2

    fixed_time: datetime | None = arguments.now
    started_at = fixed_time if fixed_time is not None else datetime.now(UTC)
    runtime_environment = os.environ if environ is None else environ
    token = runtime_environment.get("PORTFOLIO_AUDIT_GITHUB_TOKEN", "")

    if not token.strip():
        report = _minimal_incomplete_report(
            started_at,
            _finish_time(fixed_time),
            "GITHUB_APP_TOKEN_MISSING",
            "GitHub App token was unavailable",
        )
        return _write_cli_report(
            report, arguments.json_output, arguments.text_output
        )

    try:
        policy = load_policy(arguments.policy)
    except PolicyError:
        report = _minimal_incomplete_report(
            started_at,
            _finish_time(fixed_time),
            "POLICY_INVALID",
            "portfolio audit policy was invalid",
        )
        return _write_cli_report(
            report, arguments.json_output, arguments.text_output
        )

    try:
        client = GitHubClient(token)
        collection = collect_estate(policy, client)
        finished_at = _finish_time(fixed_time)
        findings = evaluate(policy, collection, finished_at)
        report = build_report(
            policy, collection, findings, started_at, finished_at
        )
    except AuthenticationError:
        code = "GITHUB_AUTHENTICATION_FAILED"
        summary = "GitHub App authentication failed"
    except AuthorisationError:
        code = "GITHUB_AUTHORISATION_FAILED"
        summary = "GitHub App authorisation failed"
    except RateLimitError:
        code = "GITHUB_RATE_LIMITED"
        summary = "GitHub rate limit prevented a complete audit"
    except ResponseError:
        code = "GITHUB_RESPONSE_INVALID"
        summary = "GitHub response could not be safely collected"
    except SafetyLimitError:
        code = "REQUEST_SAFETY_LIMIT"
        summary = "portfolio audit safety limit was reached"
    except Exception as error:
        code = "COLLECTOR_UNEXPECTED_FAILURE"
        summary = "portfolio audit collection failed unexpectedly"
        # Without this an operator saw only the generic code and could not tell
        # which operation failed or where. The exception type and the stack go to
        # stderr; the message is withheld, like everything else the sanitised report
        # leaves out, because an unexpected error can quote whatever it was handling.
        print(f"{type(error).__name__} (message withheld)", file=sys.stderr)
        traceback.print_tb(error.__traceback__, file=sys.stderr)
    else:
        return _write_cli_report(
            report, arguments.json_output, arguments.text_output
        )

    report = _minimal_incomplete_report(
        started_at,
        _finish_time(fixed_time),
        code,
        summary,
    )
    return _write_cli_report(report, arguments.json_output, arguments.text_output)


if __name__ == "__main__":
    raise SystemExit(main())
