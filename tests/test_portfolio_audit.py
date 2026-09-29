import base64
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from collections import deque
from dataclasses import asdict, replace
from datetime import UTC, date, datetime, timedelta
from http.client import HTTPMessage
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import yaml

from scripts.portfolio_audit import (
    MAX_RAW_WORKFLOW_BYTES,
    AuditReport,
    AuditStatus,
    AuthenticationError,
    AuthorisationError,
    CollectionProblem,
    CollectionResult,
    DependabotPullRequest,
    Finding,
    GitHubClient,
    HttpResponse,
    Policy,
    PolicyError,
    RateLimitError,
    ReleaseComponent,
    ReleaseDeferral,
    RepositorySnapshot,
    ResponseError,
    SafetyLimitError,
    SameOriginRedirectHandler,
    Severity,
    UrllibTransport,
    WorkflowRun,
    _normalise_runs,
    _workflow_triggers,
    build_report,
    collect_estate,
    evaluate,
    git_blob_sha,
    load_policy,
    main,
    render_json,
    render_text,
    report_to_dict,
    write_outputs,
)
from scripts.send_portfolio_audit import load_reports

WORKFLOW = b"name: Verify\njobs:\n  verify:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml@3b8a377207cab2c7c808fcc96b66578f4695beea\n"


# Local post-archive fixtures; these do not assert that remote archives occurred.
POST_ARCHIVE_REPOSITORIES = (
    ".github",
    "accounting-review-pipeline",
    "au-fpa-pack",
    "au-tax-legislation-corpus",
    "australian-accounting",
    "australian-accounting-skills",
    "github-agent-skills",
    "llm-tax-guardrails",
    "Metanoia",
    "Ozzit",
    "planning-analytics-model",
    "portfolio-audit",
    "release-policy",
    "ryanduguid",
    "ryanduguid.github.io",
)
ARCHIVED_SOURCE_REPOSITORIES = (
    "accounting-excel-toolkit",
    "ato-benchmark-compare",
    "australian-accounting-power-bi",
    "awesome-australian-accounting-tech",
    "div7a-loan-review",
    "hardhat-ledger",
    "payday-super-checker",
    "SolomonsSword",
    "TaxJarvis",
    "TheExchequerTally",
    "TheWIPTally",
    "workpaper-review-gate",
    "xero-ledger-review-gate",
    "xero-trial-balance-export",
)


def blob_sha(value: bytes) -> str:
    return hashlib.sha1(f"blob {len(value)}\0".encode("ascii") + value).hexdigest()


def public_repo(name: str = "example") -> dict[str, object]:
    return {
        "name": name,
        "default_branch": "main",
        "private": False,
        "fork": False,
        "archived": False,
        "description": "SENSITIVE-DESCRIPTION-SENTINEL",
    }


def valid_policy_dict() -> dict[str, object]:
    return {
        "schema_version": 1,
        "owner": "ryanduguid",
        "expected_repositories": [".github", "example"],
        "baseline_exemptions": {"workflow": {}, "dependabot": {}},
        "dependabot_max_age_days": 14,
        "release_policy_pins": {
            "release-python.yml": [
                "3b8a377207cab2c7c808fcc96b66578f4695beea"
            ]
        },
    }


class PolicyTests(unittest.TestCase):
    def write_policy(self, value: dict[str, object]) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "policy.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_loads_valid_policy(self) -> None:
        policy = load_policy(self.write_policy(valid_policy_dict()))
        self.assertEqual(policy.owner, "ryanduguid")
        self.assertEqual(policy.expected_repositories, (".github", "example"))
        self.assertEqual(policy.dependabot_max_age_days, 14)

    def test_rejects_unknown_top_level_key(self) -> None:
        raw = valid_policy_dict()
        raw["unexpected"] = True
        with self.assertRaisesRegex(PolicyError, "unexpected policy keys"):
            load_policy(self.write_policy(raw))

    def test_rejects_non_integer_schema_version(self) -> None:
        raw = valid_policy_dict()
        raw["schema_version"] = 1.0
        with self.assertRaisesRegex(PolicyError, "schema version"):
            load_policy(self.write_policy(raw))

    def test_rejects_boolean_schema_version(self) -> None:
        raw = valid_policy_dict()
        raw["schema_version"] = True
        with self.assertRaisesRegex(PolicyError, "schema version"):
            load_policy(self.write_policy(raw))

    def test_rejects_non_utf8_policy_file(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "policy.json"
        path.write_bytes(b"\xff")
        with self.assertRaisesRegex(PolicyError, "UTF-8 JSON"):
            load_policy(path)

    def test_rejects_unsorted_or_case_duplicate_repositories(self) -> None:
        raw = valid_policy_dict()
        raw["expected_repositories"] = ["Example", ".github", "example"]
        with self.assertRaisesRegex(PolicyError, "sorted unique repository names"):
            load_policy(self.write_policy(raw))

    def test_rejects_dot_segments_and_repository_names_over_one_hundred_characters(self) -> None:
        for invalid in (".", "..", "a" * 101):
            with self.subTest(invalid=invalid):
                raw = valid_policy_dict()
                raw["expected_repositories"] = sorted(
                    [".github", invalid], key=str.casefold
                )
                with self.assertRaisesRegex(PolicyError, "repository name"):
                    load_policy(self.write_policy(raw))

    def test_rejects_blank_or_unknown_exemption(self) -> None:
        raw = valid_policy_dict()
        raw["baseline_exemptions"] = {
            "workflow": {"missing": ""},
            "dependabot": {},
        }
        with self.assertRaisesRegex(PolicyError, "exemption"):
            load_policy(self.write_policy(raw))

    def test_rejects_non_lowercase_full_sha(self) -> None:
        raw = valid_policy_dict()
        raw["release_policy_pins"] = {"release-python.yml": ["A" * 40]}
        with self.assertRaisesRegex(PolicyError, "40 lowercase hexadecimal"):
            load_policy(self.write_policy(raw))

    def test_rejects_stale_threshold_above_timedelta_maximum(self) -> None:
        raw = valid_policy_dict()
        raw["dependabot_max_age_days"] = timedelta.max.days + 1

        with self.assertRaisesRegex(
            PolicyError, "dependabot maximum age must be a positive integer"
        ):
            load_policy(self.write_policy(raw))

    def test_repository_policy_file_is_valid(self) -> None:
        policy = load_policy(Path("portfolio-audit-policy.json"))
        self.assertEqual(len(policy.expected_repositories), 15)
        self.assertIn("portfolio-audit", policy.expected_repositories)
        self.assertIn("Metanoia", policy.expected_repositories)
        self.assertIn("ryanduguid", policy.expected_repositories)
        self.assertNotIn("div7a-loan-review", policy.expected_repositories)
        self.assertIn("github-agent-skills", policy.expected_repositories)
        self.assertNotIn("TaxJarvis", policy.expected_repositories)
        self.assertNotIn("DiogenesLamp", policy.expected_repositories)
        self.assertIn("au-fpa-pack", policy.expected_repositories)
        self.assertIn("llm-tax-guardrails", policy.expected_repositories)
        self.assertIn("planning-analytics-model", policy.expected_repositories)
        self.assertNotIn(
            "awesome-australian-accounting-tech", policy.expected_repositories
        )
        self.assertEqual(
            set(policy.release_policy_pins),
            {
                "attribution-policy.yml",
                "release-archive.yml",
                "release-python.yml",
                "release-skills.yml",
                "verify-skills.yml",
            },
        )

    def test_accepts_scoped_tagged_release_workflows_and_legacy_policies(self) -> None:
        raw = valid_policy_dict()
        self.assertEqual(load_policy(self.write_policy(raw)).tagged_release_workflows, {})
        raw["tagged_release_workflows"] = {
            "example": {"release.yml": "v", "publish.yml": "example/v"}
        }
        policy = load_policy(self.write_policy(raw))
        self.assertEqual(
            policy.tagged_release_workflows,
            {"example": {"release.yml": "v", "publish.yml": "example/v"}},
        )

    def test_rejects_unscoped_or_malformed_tagged_release_policy(self) -> None:
        invalid_maps: tuple[object, ...] = (
            None, [], {"unknown": {"release.yml": "v"}},
            {"example": []}, {"example": {}},
            {"example": {"../release.yml": "v"}},
            {"example": {".github/workflows/release.yml": "v"}},
            {"example": {"release.yml": None}},
            {"example": {"release.yml": ""}},
            {"example": {"release.yml": "*"}},
            {"example": {"release.yml": "../v"}},
            {"example": {"release.yml": "example/*"}},
            {"example": {"release.yml": "example//v"}},
        )
        for value in invalid_maps:
            with self.subTest(value=value):
                raw = valid_policy_dict()
                raw["tagged_release_workflows"] = value
                with self.assertRaisesRegex(PolicyError, "tagged release"):
                    load_policy(self.write_policy(raw))

    def test_accepts_a_release_queue_and_defaults_without_one(self) -> None:
        raw = valid_policy_dict()
        policy = load_policy(self.write_policy(raw))
        self.assertEqual((policy.release_max_age_days, policy.release_components, policy.release_deferrals), (7, {}, {}))
        raw["tagged_release_workflows"] = {"example": {"release.yml": "v"}}
        raw["release_queue"] = {
            "max_age_days": 10,
            "components": {"example": {"release.yml": {
                "paths": ["pkg", ".claude-plugin/plugin.json"], "version_file": "pkg/version.py",
            }}},
            "deferrals": {"example": {"release.yml": {"reason": " preparing v1 ", "review_by": "2026-10-31"}}},
        }
        policy = load_policy(self.write_policy(raw))
        self.assertEqual(policy.release_max_age_days, 10)
        self.assertEqual(
            policy.release_components,
            {"example": {"release.yml": ReleaseComponent(("pkg", ".claude-plugin/plugin.json"), "pkg/version.py")}},
        )
        self.assertEqual(
            policy.release_deferrals,
            {"example": {"release.yml": ReleaseDeferral("preparing v1", date(2026, 10, 31))}},
        )

    def test_rejects_malformed_release_queue(self) -> None:
        def queue(**changes: object) -> dict[str, object]:
            return {
                "max_age_days": 7,
                "components": {"example": {"release.yml": {"paths": ["pkg"], "version_file": "VERSION"}}},
                "deferrals": {},
                **changes,
            }

        def component(**changes: object) -> dict[str, object]:
            return queue(components={"example": {"release.yml": {"paths": ["pkg"], "version_file": "VERSION", **changes}}})

        invalid: tuple[object, ...] = (
            None, [], {"max_age_days": 7, "components": {}}, queue(extra=1),
            queue(max_age_days=0), queue(max_age_days=True), queue(max_age_days="7"),
            queue(components=[]), queue(components={"example": {}}), queue(components={"example": []}),
            queue(components={"example": {"release.yml": ["pkg"]}}),
            queue(components={"example": {"publish.yml": {"paths": ["pkg"], "version_file": "VERSION"}}}),
            queue(components={".github": {"release.yml": {"paths": ["pkg"], "version_file": "VERSION"}}}),
            queue(components={"example": {"release.yml": {"paths": ["pkg"]}}}),
            component(extra=1),
            *(component(paths=value) for value in (
                [], "pkg", ["pkg", "pkg"], [""], ["/pkg"], ["pkg/"], ["a//b"], ["a/../b"],
                ["./pkg"], ["pkg/*"], ["a\\b"], [7], ["pkg", ["nested"]], [{"path": "pkg"}],
            )),
            *(component(version_file=value) for value in (
                None, "", "setup.cfg", "pkg/version.txt", "/VERSION", "../VERSION", "pkg/*.py",
            )),
            queue(deferrals=[]), queue(deferrals={"example": {}}),
            queue(deferrals={"example": {"publish.yml": {"reason": "r", "review_by": "2026-10-31"}}}),
            *(queue(deferrals={"example": {"release.yml": value}}) for value in (
                "defer", {"reason": "r"}, {"reason": "r", "review_by": "2026-10-31", "extra": 1},
                {"reason": " ", "review_by": "2026-10-31"}, {"reason": "r", "review_by": "31/10/2026"},
                {"reason": "r", "review_by": "2026-02-30"}, {"reason": "r", "review_by": 20261031},
            )),
        )
        for value in invalid:
            with self.subTest(value=value):
                raw = valid_policy_dict()
                raw["tagged_release_workflows"] = {"example": {"release.yml": "v"}}
                raw["release_queue"] = value
                with self.assertRaisesRegex(PolicyError, "release"):
                    load_policy(self.write_policy(raw))

    def test_live_policy_queues_every_release_caller(self) -> None:
        policy = load_policy(Path("portfolio-audit-policy.json"))
        tagged = {(repository, workflow) for repository, workflows in policy.tagged_release_workflows.items() for workflow in workflows}
        queued = {(repository, workflow) for repository, workflows in policy.release_components.items() for workflow in workflows}
        self.assertEqual(len(tagged), 18)
        self.assertEqual(queued, tagged)

    def test_cutover_inventory_and_approved_pin_do_not_raise_false_actions(self) -> None:
        policy = load_policy(Path("portfolio-audit-policy.json"))
        discovered = POST_ARCHIVE_REPOSITORIES
        for family in ("release-archive.yml", "release-python.yml", "release-skills.yml", "verify-skills.yml"):
            with self.subTest(family=family):
                repository = replace(
                    snapshot(workflow_source=(
                        "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/"
                        f"{family}@787db4590e725cfd37104c8a9dd9e75f7fd4c018\n"
                    )),
                    name="australian-accounting",
                )
                result = replace(collection(repository), discovered_repositories=discovered)
                findings = evaluate(policy, result, datetime(2026, 9, 3, tzinfo=UTC))
                self.assertEqual([item.code for item in findings if item.severity == Severity.ACTION], [])

    def test_post_archive_inventory_reports_missing_active_repositories(self) -> None:
        policy = load_policy(Path("portfolio-audit-policy.json"))
        for missing in POST_ARCHIVE_REPOSITORIES:
            with self.subTest(missing=missing):
                result = CollectionResult(
                    discovered_repositories=tuple(
                        name for name in POST_ARCHIVE_REPOSITORIES if name != missing
                    ),
                    repositories=(),
                    problems=(),
                    request_count=0,
                    rate_limit={},
                )
                findings = evaluate(policy, result, datetime(2026, 9, 3, tzinfo=UTC))
                self.assertEqual(
                    [(item.repository, item.code, item.severity) for item in findings],
                    [(missing, "EXPECTED_REPOSITORY_MISSING", Severity.ACTION)],
                )

    def test_post_archive_inventory_reports_unexpected_active_repositories(self) -> None:
        policy = load_policy(Path("portfolio-audit-policy.json"))
        for unexpected in (*ARCHIVED_SOURCE_REPOSITORIES, "unexpected-fixture"):
            with self.subTest(unexpected=unexpected):
                result = CollectionResult(
                    discovered_repositories=(*POST_ARCHIVE_REPOSITORIES, unexpected),
                    repositories=(),
                    problems=(),
                    request_count=0,
                    rate_limit={},
                )
                findings = evaluate(policy, result, datetime(2026, 9, 3, tzinfo=UTC))
                self.assertEqual(
                    [(item.repository, item.code, item.severity) for item in findings],
                    [(unexpected, "UNEXPECTED_REPOSITORY", Severity.ACTION)],
                )

    def test_archived_excel_tag_rule_cannot_be_restored(self) -> None:
        raw = json.loads(Path("portfolio-audit-policy.json").read_text(encoding="utf-8"))
        raw["tagged_release_workflows"]["accounting-excel-toolkit"] = {
            "release.yml": "v"
        }
        with self.assertRaisesRegex(PolicyError, "tagged release workflows"):
            load_policy(self.write_policy(raw))


class ReportModelTests(unittest.TestCase):
    def test_report_dictionary_is_stable_and_uses_zulu_time(self) -> None:
        when = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
        report = AuditReport(
            schema_version=1,
            owner="ryanduguid",
            started_at=when,
            finished_at=when,
            repository_count=1,
            request_count=4,
            rate_limit={"limit": "5000", "remaining": "4900", "reset": "1"},
            status=AuditStatus.ACTION_REQUIRED,
            findings=(
                Finding(
                    Severity.ACTION,
                    "example",
                    "DEPENDABOT_BASELINE_MISSING",
                    "missing .github/dependabot.yml",
                    "https://github.com/ryanduguid/example",
                ),
            ),
            collection_errors=(
                CollectionProblem("RAW_FILE_MISMATCH", "example", "workflow changed"),
            ),
        )
        value = report_to_dict(report)
        self.assertEqual(value["started_at"], "2026-08-26T12:00:00Z")
        self.assertEqual(value["status"], "ACTION_REQUIRED")
        self.assertNotIn("raw_response", json.dumps(value))


class FakeTransport:
    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = deque(responses)
        self.requests: list[tuple[str, dict[str, str]]] = []

    def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
        self.requests.append((url, headers))
        return self.responses.popleft()


def api_response(value: object, *, remaining: int = 4999, link: str = "") -> HttpResponse:
    headers = {
        "X-RateLimit-Limit": "5000",
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset": "1787749200",
    }
    if link:
        headers["Link"] = link
    return HttpResponse(200, headers, json.dumps(value).encode("utf-8"))


def collection_transport(
    *,
    raw: bytes = WORKFLOW,
    truncated: bool = False,
    run_response: HttpResponse | None = None,
    pull_responses: tuple[HttpResponse, ...] | None = None,
) -> FakeTransport:
    if run_response is None:
        run_response = api_response(
            {
                "workflow_runs": [
                    {
                        "id": 42,
                        "path": ".github/workflows/verify.yml",
                        "conclusion": "success",
                        "status": "completed",
                        "created_at": "2026-08-26T12:00:00Z",
                        "head_branch": "main",
                        "event": "push",
                        "head_commit": {"message": "SENSITIVE-COMMIT-SENTINEL"},
                    }
                ]
            }
        )
    if pull_responses is None:
        pull_responses = (
            api_response(
                [
                    {
                        "number": 7,
                        "created_at": "2026-08-01T00:00:00Z",
                        "user": {"login": "dependabot[bot]"},
                        "title": "SENSITIVE-PR-SENTINEL",
                        "body": "SENSITIVE-BODY-SENTINEL",
                    },
                    {
                        "number": 8,
                        "created_at": "2026-08-02T00:00:00Z",
                        "user": {"login": "human"},
                        "body": "SENSITIVE-HUMAN-BODY-SENTINEL",
                    },
                ]
            ),
        )
    return FakeTransport(
        [
            api_response([public_repo()]),
            api_response(
                {
                    "sha": "tree-sha",
                    "truncated": truncated,
                    "tree": [
                        {
                            "path": ".github/workflows/verify.yml",
                            "type": "blob",
                            "sha": blob_sha(WORKFLOW),
                        },
                        {
                            "path": ".github/dependabot.yml",
                            "type": "blob",
                            "sha": "dependabot-sha",
                        },
                        {
                            "path": "src/private-looking-name.py",
                            "type": "blob",
                            "sha": "source-sha",
                        },
                    ],
                }
            ),
            HttpResponse(200, {}, raw),
            run_response,
            *pull_responses,
        ]
    )


def repository_tree_transport(
    tree: list[dict[str, object]],
    *,
    raw: bytes = WORKFLOW,
    workflow_lookup: HttpResponse | None = None,
) -> FakeTransport:
    class RoutingTransport(FakeTransport):
        def __init__(self) -> None:
            super().__init__([])

        def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
            self.requests.append((url, headers))
            if "/users/ryanduguid/repos" in url:
                return api_response([public_repo()])
            if "/git/trees/" in url:
                return api_response(
                    {"sha": "tree-sha", "truncated": False, "tree": tree}
                )
            if url.startswith("https://raw.githubusercontent.com/"):
                return HttpResponse(200, {}, raw)
            if "/actions/workflows/" in url and workflow_lookup is not None:
                return workflow_lookup
            if "/actions/runs" in url or "/actions/workflows/" in url:
                return api_response({"workflow_runs": []})
            if "/pulls" in url:
                return api_response([])
            raise AssertionError(f"unexpected request URL: {url}")

    return RoutingTransport()


class GitHubClientTests(unittest.TestCase):
    def test_rejects_caller_relaxation_of_safety_limits(self) -> None:
        cases = (
            ({"max_pages": 11}, "maximum pages"),
            ({"max_requests": 1_001}, "maximum requests"),
            ({"rate_headroom": 99}, "rate headroom"),
        )
        for options, message in cases:
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, message):
                    GitHubClient("token", transport=FakeTransport([]), **options)

    def test_transport_exception_cannot_leak_bearer_token(self) -> None:
        class LeakyTransport:
            def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
                raise AuthenticationError(
                    f"LEAKY-TRANSPORT-SENTINEL BODY-SENTINEL {headers['Authorization']}"
                )

        client = GitHubClient("TOKEN-SENTINEL", transport=LeakyTransport())
        with self.assertRaises(ResponseError) as raised:
            client.get_json("/user")
        self.assertEqual(str(raised.exception), "HTTP request failed")
        self.assertNotIn("LEAKY-TRANSPORT-SENTINEL", str(raised.exception))
        self.assertNotIn("BODY-SENTINEL", str(raised.exception))
        self.assertNotIn("TOKEN-SENTINEL", str(raised.exception))

    def test_oversized_rate_headers_fail_with_a_typed_error(self) -> None:
        oversized_value = "9" * 5_000
        for header in (
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
        ):
            with self.subTest(header=header):
                headers = dict(api_response({}).headers)
                headers[header] = oversized_value
                client = GitHubClient(
                    "token",
                    transport=FakeTransport([HttpResponse(200, headers, b"{}")]),
                )
                with self.assertRaises(RateLimitError) as raised:
                    client.get_json("/user")
                self.assertNotIn(oversized_value, str(raised.exception))

    def test_oversized_403_rate_header_fails_with_a_typed_error(self) -> None:
        oversized_value = "9" * 5_000
        response = HttpResponse(
            403,
            {**api_response({}).headers, "x-ratelimit-remaining": oversized_value},
            b'{"message":"forbidden"}',
        )
        client = GitHubClient("token", transport=FakeTransport([response]))
        with self.assertRaises(RateLimitError) as raised:
            client.get_json("/user")
        self.assertNotIn(oversized_value, str(raised.exception))

    def test_rest_request_uses_bearer_token_and_fixed_headers(self) -> None:
        transport = FakeTransport([api_response({"ok": True})])
        client = GitHubClient("installation-token", transport=transport)
        self.assertEqual(client.get_json("/rate_limit"), {"ok": True})
        _, headers = transport.requests[0]
        self.assertEqual(headers["Authorization"], "Bearer installation-token")
        self.assertEqual(headers["X-GitHub-Api-Version"], "2022-11-28")

    def test_query_parameters_precede_a_url_fragment(self) -> None:
        transport = FakeTransport([api_response({"ok": True})])
        client = GitHubClient("token", transport=transport)
        client.get_json("/items#section", {"name": "a/b"})
        url, _ = transport.requests[0]
        self.assertEqual(url, "https://api.github.com/items?name=a%2Fb#section")

    def test_raw_request_never_sends_authorisation(self) -> None:
        transport = FakeTransport([HttpResponse(200, {}, b"workflow")])
        client = GitHubClient("installation-token", transport=transport)
        self.assertEqual(client.get_raw_bytes("https://raw.githubusercontent.com/a/b/c/d"), b"workflow")
        _, headers = transport.requests[0]
        self.assertNotIn("Authorization", headers)

    def test_missing_rate_headers_fail_closed(self) -> None:
        client = GitHubClient("token", transport=FakeTransport([HttpResponse(200, {}, b"{}")]))
        with self.assertRaisesRegex(RateLimitError, "missing rate-limit headers"):
            client.get_json("/user")

    def test_rate_header_names_are_case_insensitive(self) -> None:
        response = HttpResponse(
            200,
            {
                "x-ratelimit-limit": "5000",
                "X-RATELIMIT-Remaining": "4999",
                "x-Ratelimit-Reset": "1787749200",
            },
            b"{}",
        )
        client = GitHubClient("token", transport=FakeTransport([response]))
        self.assertEqual(client.get_json("/user"), {})
        self.assertEqual(client.rate_limit["remaining"], "4999")

    def test_401_never_retries_or_falls_back(self) -> None:
        transport = FakeTransport([HttpResponse(401, {}, b'{"message":"bad credentials"}')])
        client = GitHubClient("token", transport=transport)
        with self.assertRaises(AuthenticationError):
            client.get_json("/user")
        self.assertEqual(len(transport.requests), 1)

    def test_malformed_json_fails_closed(self) -> None:
        response_headers = api_response({}).headers
        client = GitHubClient(
            "token",
            transport=FakeTransport(
                [HttpResponse(200, response_headers, b"not-json")]
            ),
        )
        with self.assertRaises(ResponseError):
            client.get_json("/user")

    def test_non_standard_json_constants_fail_closed(self) -> None:
        response_headers = api_response({}).headers
        client = GitHubClient(
            "token",
            transport=FakeTransport([HttpResponse(200, response_headers, b'{"value": NaN}')]),
        )
        with self.assertRaises(ResponseError):
            client.get_json("/user")

    def test_permission_403_is_authorisation_not_rate_limit(self) -> None:
        response = HttpResponse(
            403,
            api_response({}).headers,
            b'{"message":"Resource not accessible by integration"}',
        )
        client = GitHubClient("token", transport=FakeTransport([response]))
        with self.assertRaises(AuthorisationError):
            client.get_json("/user")

    def test_primary_secondary_and_429_limits_are_rate_failures(self) -> None:
        cases = (
            HttpResponse(
                403,
                api_response({}, remaining=0).headers,
                b'{"message":"API rate limit exceeded"}',
            ),
            HttpResponse(
                403,
                {**api_response({}).headers, "Retry-After": "60"},
                b'{"message":"secondary rate limit"}',
            ),
            HttpResponse(429, api_response({}).headers, b"{}"),
        )
        for response in cases:
            with self.subTest(status=response.status, headers=response.headers):
                client = GitHubClient("token", transport=FakeTransport([response]))
                with self.assertRaises(RateLimitError):
                    client.get_json("/user")

    def test_numeric_zero_rate_header_is_a_rate_failure(self) -> None:
        response = HttpResponse(
            403,
            {**api_response({}).headers, "X-RateLimit-Remaining": "000"},
            b'{"message":"forbidden"}',
        )
        client = GitHubClient("token", transport=FakeTransport([response]))
        with self.assertRaises(RateLimitError):
            client.get_json("/user")

    def test_known_reserve_is_checked_before_the_next_request(self) -> None:
        transport = FakeTransport(
            [api_response({"page": 1}, remaining=100), api_response({"page": 2})]
        )
        client = GitHubClient("token", transport=transport)
        client.get_json("/first")
        with self.assertRaisesRegex(RateLimitError, "100-request headroom"):
            client.get_json("/second")
        self.assertEqual(len(transport.requests), 1)

    def test_successful_final_response_below_reserve_is_incomplete(self) -> None:
        transport = FakeTransport([api_response({"ok": True}, remaining=99)])
        client = GitHubClient("token", transport=transport)
        with self.assertRaisesRegex(RateLimitError, "fell below 100-request headroom"):
            client.get_json("/final")
        self.assertEqual(len(transport.requests), 1)

    def test_request_ceiling_rejects_before_transport(self) -> None:
        transport = FakeTransport(
            [api_response({"page": 1}, remaining=4999), api_response({"page": 2})]
        )
        client = GitHubClient("token", transport=transport, max_requests=1)
        client.get_json("/first")
        with self.assertRaisesRegex(SafetyLimitError, "request ceiling"):
            client.get_json("/second")
        self.assertEqual(len(transport.requests), 1)

    def test_cross_host_redirect_is_rejected_before_forwarding_authorisation(self) -> None:
        handler = SameOriginRedirectHandler()
        request = urllib.request.Request(
            "https://api.github.com/user",
            headers={"Authorization": "Bearer SENSITIVE-TOKEN-SENTINEL"},
        )
        with self.assertRaisesRegex(ResponseError, "cross-origin redirect"):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                HTTPMessage(),
                "https://example.invalid/capture",
            )

    def test_malformed_redirect_is_a_body_free_response_error(self) -> None:
        handler = SameOriginRedirectHandler()
        request = urllib.request.Request("https://api.github.com/user")
        with self.assertRaisesRegex(ResponseError, "cross-origin redirect"):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                HTTPMessage(),
                "https://api.github.com:not-a-port/user",
            )

    def test_network_failure_becomes_body_free_response_error(self) -> None:
        class FailingOpener:
            def open(self, request: object, *, timeout: int) -> object:
                raise urllib.error.URLError("SENSITIVE-NETWORK-SENTINEL")

        transport = UrllibTransport(opener=FailingOpener())
        with self.assertRaises(ResponseError) as raised:
            transport.request("https://api.github.com/user", {})
        self.assertNotIn("SENSITIVE-NETWORK-SENTINEL", str(raised.exception))

    def test_transport_rejects_an_oversized_response_body(self) -> None:
        class OversizedResponse:
            status = 200
            headers: dict[str, str] = {}

            def __enter__(self) -> "OversizedResponse":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self, amount: int) -> bytes:
                return b"x" * amount

        class OversizedOpener:
            def open(self, request: object, *, timeout: int) -> OversizedResponse:
                return OversizedResponse()

        transport = UrllibTransport(opener=OversizedOpener(), max_response_bytes=8)
        with self.assertRaisesRegex(ResponseError, "response exceeded"):
            transport.request("https://api.github.com/user", {})

    def test_raw_workflow_body_has_a_tighter_ceiling(self) -> None:
        transport = FakeTransport(
            [HttpResponse(200, {}, b"x" * (MAX_RAW_WORKFLOW_BYTES + 1))]
        )
        client = GitHubClient("token", transport=transport)
        with self.assertRaisesRegex(ResponseError, "workflow source exceeded"):
            client.get_raw_bytes("https://raw.githubusercontent.com/o/r/main/w.yml")


class PaginationTests(unittest.TestCase):
    def test_follows_same_host_next_link(self) -> None:
        transport = FakeTransport(
            [
                api_response(
                    [{"id": 1}],
                    link='<https://api.github.com/items?page=2>; rel="next"',
                ),
                api_response([{"id": 2}]),
            ]
        )
        client = GitHubClient("token", transport=transport)
        self.assertEqual(client.paginate("/items"), ({"id": 1}, {"id": 2}))

    def test_rejects_more_than_ten_pages(self) -> None:
        responses = [
            api_response(
                [{"id": number}],
                link=f'<https://api.github.com/items?page={number + 1}>; rel="next"',
            )
            for number in range(1, 12)
        ]
        client = GitHubClient("token", transport=FakeTransport(responses))
        with self.assertRaisesRegex(SafetyLimitError, "10 pages"):
            client.paginate("/items")

    def test_rejects_cross_host_next_link(self) -> None:
        response = api_response(
            [{"id": 1}],
            link='<https://example.invalid/items?page=2>; rel="next"',
        )
        client = GitHubClient("token", transport=FakeTransport([response]))
        with self.assertRaisesRegex(ResponseError, "left api.github.com"):
            client.paginate("/items")

    def test_rejects_non_list_page(self) -> None:
        client = GitHubClient("token", transport=FakeTransport([api_response({})]))
        with self.assertRaisesRegex(ResponseError, "page was not a list"):
            client.paginate("/items")

    def test_pagination_stops_when_headroom_is_reached(self) -> None:
        transport = FakeTransport(
            [
                api_response(
                    [{"id": 1}],
                    remaining=100,
                    link='<https://api.github.com/items?page=2>; rel="next"',
                ),
                api_response([{"id": 2}]),
            ]
        )
        client = GitHubClient("token", transport=transport)
        with self.assertRaisesRegex(RateLimitError, "100-request headroom"):
            client.paginate("/items")
        self.assertEqual(len(transport.requests), 1)

    def test_capacity_reserves_one_hundred_requests(self) -> None:
        client = GitHubClient("token", transport=FakeTransport([api_response({"ok": True}, remaining=175)]))
        client.get_json("/rate_limit")
        with self.assertRaisesRegex(RateLimitError, "100-request headroom"):
            client.require_capacity(76)


class WorkflowRunNormalisationTests(unittest.TestCase):
    def test_ignores_github_managed_dynamic_workflows(self) -> None:
        runs = _normalise_runs(
            {
                "workflow_runs": [
                    {
                        "id": 1,
                        "path": "dynamic/dependabot/dependabot-updates",
                        "conclusion": "success",
                    },
                    {
                        "id": 2,
                        "path": "dynamic/github-code-scanning/codeql",
                        "conclusion": "success",
                    },
                    {
                        "id": 3,
                        "path": ".github/workflows/ci.yml",
                        "conclusion": "failure",
                        "status": "completed",
                        "created_at": "2026-08-26T12:00:00Z",
                    },
                ]
            }
        )

        self.assertEqual(runs, (WorkflowRun(3, ".github/workflows/ci.yml", "failure", datetime(2026, 8, 26, 12, tzinfo=UTC)),))

    def test_rejects_an_invalid_repository_workflow_path(self) -> None:
        with self.assertRaisesRegex(ResponseError, "workflow path was invalid"):
            _normalise_runs(
                {
                    "workflow_runs": [
                        {"id": 1, "path": "ci.yml", "conclusion": "success"}
                    ]
                }
            )

class CollectorTests(unittest.TestCase):
    def test_collects_only_normalised_public_evidence(self) -> None:
        transport = collection_transport()
        client = GitHubClient("token", transport=transport)
        result = collect_estate(load_policy(Path("portfolio-audit-policy.json")), client)
        repository = next(item for item in result.repositories if item.name == "example")
        self.assertIn(".github/workflows/verify.yml", repository.paths)
        self.assertNotIn("src/private-looking-name.py", repository.workflow_sources)
        self.assertEqual(repository.workflow_runs[0].run_id, 42)
        self.assertEqual(repository.dependabot_pull_requests[0].number, 7)
        run_urls = [url for url, _headers in transport.requests if "/actions/runs?" in url]
        self.assertEqual(len(run_urls), 1)
        self.assertIn("branch=main", run_urls[0])
        serialised = json.dumps(asdict(result), default=str)
        for sentinel in (
            "SENSITIVE-DESCRIPTION-SENTINEL",
            "SENSITIVE-COMMIT-SENTINEL",
            "SENSITIVE-PR-SENTINEL",
            "SENSITIVE-BODY-SENTINEL",
            "SENSITIVE-HUMAN-BODY-SENTINEL",
        ):
            self.assertNotIn(sentinel, serialised)

    def test_filters_private_forked_and_archived_repositories(self) -> None:
        values = [
            {**public_repo("private"), "private": True},
            {**public_repo("fork"), "fork": True},
            {**public_repo("archive"), "archived": True},
        ]
        client = GitHubClient("token", transport=FakeTransport([api_response(values)]))
        policy = load_policy(Path("portfolio-audit-policy.json"))
        result = collect_estate(policy, client)
        self.assertEqual(result.discovered_repositories, ())
        self.assertEqual(result.repositories, ())

    def test_truncated_tree_records_incomplete_problem(self) -> None:
        client = GitHubClient("token", transport=collection_transport(truncated=True))
        result = collect_estate(load_policy(Path("portfolio-audit-policy.json")), client)
        self.assertIn("TREE_TRUNCATED", {problem.code for problem in result.problems})

    def test_workflow_count_over_the_bound_records_a_problem_and_skips_fetches(self) -> None:
        tree: list[dict[str, object]] = [
            {"path": f".github/workflows/w{index}.yml", "type": "blob", "sha": blob_sha(WORKFLOW)}
            for index in range(3)
        ]
        transport = repository_tree_transport(tree)
        client = GitHubClient("token", transport=transport)
        with patch("scripts.portfolio_audit.MAX_WORKFLOWS_PER_REPOSITORY", 2):
            result = collect_estate(load_policy(Path("portfolio-audit-policy.json")), client)
        self.assertIn("WORKFLOW_COUNT_EXCEEDED", {problem.code for problem in result.problems})
        self.assertFalse(
            any(
                url.startswith("https://raw.githubusercontent.com/")
                for url, _headers in transport.requests
            ),
            "the workflow fetch loop must be skipped when the count bound is exceeded",
        )

    def test_raw_fetch_counts_toward_the_request_ceiling(self) -> None:
        client = GitHubClient(
            "token",
            transport=FakeTransport([api_response({}), HttpResponse(200, {}, b"raw bytes")]),
        )
        client.get_json("/user")
        before = client.request_count
        client.get_raw_bytes(
            "https://raw.githubusercontent.com/ryanduguid/example/main/.github/workflows/verify.yml"
        )
        self.assertEqual(client.request_count, before + 1)

    def test_denied_repository_is_discovered_but_incomplete(self) -> None:
        transport = FakeTransport(
            [
                api_response([public_repo("new-public-repository")]),
                HttpResponse(
                    403,
                    {
                        "X-RateLimit-Limit": "5000",
                        "X-RateLimit-Remaining": "4999",
                        "X-RateLimit-Reset": "1787749200",
                    },
                    b"{}",
                ),
            ]
        )
        result = collect_estate(
            load_policy(Path("portfolio-audit-policy.json")),
            GitHubClient("token", transport=transport),
        )
        self.assertEqual(result.discovered_repositories, ("new-public-repository",))
        self.assertIn("REPOSITORY_ACCESS_DENIED", {problem.code for problem in result.problems})

    def test_repository_listing_follows_pagination(self) -> None:
        transport = FakeTransport(
            [
                api_response(
                    [],
                    link='<https://api.github.com/users/ryanduguid/repos?page=2>; rel="next"',
                ),
                api_response([]),
            ]
        )
        result = collect_estate(
            load_policy(Path("portfolio-audit-policy.json")),
            GitHubClient("token", transport=transport),
        )
        self.assertEqual(result.discovered_repositories, ())
        self.assertEqual(len(transport.requests), 2)

    def test_dependabot_pull_requests_follow_pagination(self) -> None:
        pull_responses = (
            api_response(
                [],
                link='<https://api.github.com/repos/ryanduguid/example/pulls?page=2>; rel="next"',
            ),
            api_response(
                [
                    {
                        "number": 9,
                        "created_at": "2026-08-03T00:00:00Z",
                        "user": {"login": "dependabot[bot]"},
                    }
                ]
            ),
        )
        result = collect_estate(
            load_policy(Path("portfolio-audit-policy.json")),
            GitHubClient(
                "token",
                transport=collection_transport(pull_responses=pull_responses),
            ),
        )
        self.assertEqual(result.repositories[0].dependabot_pull_requests[0].number, 9)

    def test_more_than_one_hundred_active_repositories_stops_before_collection(self) -> None:
        transport = FakeTransport(
            [api_response([public_repo(f"repository-{index:03d}") for index in range(101)])]
        )
        result = collect_estate(
            load_policy(Path("portfolio-audit-policy.json")),
            GitHubClient("token", transport=transport),
        )
        self.assertEqual(result.repositories, ())
        self.assertIn("ESTATE_LIMIT_EXCEEDED", {problem.code for problem in result.problems})
        self.assertEqual(len(transport.requests), 1)

    def test_tagged_workflows_reserve_bounded_request_capacity_before_collection(self) -> None:
        # One tag listing per repository, then a run query and a branch check per
        # workflow, then a version file, a tag commit and bounded commit pages
        # per path of each queued component.
        cases: tuple[tuple[dict[str, str], dict[str, ReleaseComponent], int], ...] = (
            ({"release.yml": "v"}, {}, 114),
            ({"release.yml": "v", "publish.yml": "example/v"}, {}, 116),
            ({"release.yml": "v"}, {"release.yml": ReleaseComponent(("pkg",), "VERSION")}, 126),
        )
        for workflows, queued, remaining in cases:
            with self.subTest(workflows=workflows, queued=queued):
                policy = replace(
                    small_policy(), tagged_release_workflows={"example": workflows},
                    release_components={"example": queued} if queued else {},
                )
                transport = FakeTransport([api_response([public_repo()], remaining=remaining)])
                result = collect_estate(policy, GitHubClient("token", transport=transport))
                self.assertEqual(result.repositories, ())
                self.assertEqual([problem.code for problem in result.problems], ["GITHUB_RATE_LIMITED"])
                self.assertEqual(len(transport.requests), 1)

    def test_inactive_tagged_workflows_do_not_reserve_requests(self) -> None:
        policy = replace(small_policy(), tagged_release_workflows={"archive": {"release.yml": "v"}})
        transport = collection_transport()
        transport.responses[0] = api_response(
            [public_repo(), {**public_repo("archive"), "archived": True}], remaining=103,
        )
        result = collect_estate(policy, GitHubClient("token", transport=transport))
        self.assertEqual(result.problems, ())
        self.assertEqual([item.name for item in result.repositories], ["example"])

    def test_malformed_identifiers_make_collection_incomplete(self) -> None:
        for invalid in (".", "..", "../escape", "a" * 101):
            with self.subTest(invalid=invalid):
                malformed_repository = {
                    **public_repo(invalid),
                    "default_branch": "main",
                }
                result = collect_estate(
                    load_policy(Path("portfolio-audit-policy.json")),
                    GitHubClient(
                        "token",
                        transport=FakeTransport(
                            [api_response([malformed_repository])]
                        ),
                    ),
                )
                self.assertIn(
                    "GITHUB_RESPONSE_INVALID",
                    {problem.code for problem in result.problems},
                )

    def test_non_positive_or_boolean_run_ids_are_rejected(self) -> None:
        for invalid in (0, -1, True):
            with self.subTest(invalid=invalid):
                transport = collection_transport(
                    run_response=api_response(
                        {
                            "workflow_runs": [
                                {
                                    "id": invalid,
                                    "path": ".github/workflows/verify.yml",
                                    "conclusion": "success",
                                }
                            ]
                        }
                    )
                )
                result = collect_estate(
                    load_policy(Path("portfolio-audit-policy.json")),
                    GitHubClient("token", transport=transport),
                )
                self.assertIn(
                    "GITHUB_RESPONSE_INVALID",
                    {problem.code for problem in result.problems},
                )

    def test_unhashable_workflow_conclusion_is_rejected(self) -> None:
        result = collect_estate(
            load_policy(Path("portfolio-audit-policy.json")),
            GitHubClient(
                "token",
                transport=collection_transport(
                    run_response=api_response(
                        {
                            "workflow_runs": [
                                {
                                    "id": 42,
                                    "path": ".github/workflows/verify.yml",
                                    "conclusion": ["success"],
                                }
                            ]
                        }
                    )
                ),
            ),
        )
        self.assertIn(
            "GITHUB_RESPONSE_INVALID", {problem.code for problem in result.problems}
        )

    def test_unhashable_tree_entry_type_is_rejected(self) -> None:
        result = collect_estate(
            load_policy(Path("portfolio-audit-policy.json")),
            GitHubClient(
                "token",
                transport=FakeTransport(
                    [
                        api_response([public_repo()]),
                        api_response(
                            {
                                "truncated": False,
                                "tree": [
                                    {
                                        "path": ".github/workflows/verify.yml",
                                        "type": ["blob"],
                                        "sha": blob_sha(WORKFLOW),
                                    }
                                ],
                            }
                        ),
                    ]
                ),
            ),
        )
        self.assertIn(
            "GITHUB_RESPONSE_INVALID", {problem.code for problem in result.problems}
        )

    def test_non_positive_or_boolean_pull_request_ids_are_rejected(self) -> None:
        for invalid in (0, -1, True):
            with self.subTest(invalid=invalid):
                result = collect_estate(
                    load_policy(Path("portfolio-audit-policy.json")),
                    GitHubClient(
                        "token",
                        transport=collection_transport(
                            pull_responses=(
                                api_response(
                                    [
                                        {
                                            "number": invalid,
                                            "created_at": "2026-08-03T00:00:00Z",
                                            "user": {"login": "dependabot[bot]"},
                                        }
                                    ]
                                ),
                            )
                        ),
                    ),
                )
                self.assertIn(
                    "GITHUB_RESPONSE_INVALID",
                    {problem.code for problem in result.problems},
                )

    def test_nested_workflow_blob_cannot_satisfy_the_workflow_baseline(self) -> None:
        nested_path = ".github/workflows/archive/old.yml"
        transport = repository_tree_transport(
            [
                {"path": nested_path, "type": "blob", "sha": blob_sha(WORKFLOW)},
                {
                    "path": ".github/dependabot.yml",
                    "type": "blob",
                    "sha": "dependabot-sha",
                },
            ]
        )
        policy = replace(small_policy(), expected_repositories=("example",))

        result = collect_estate(policy, GitHubClient("token", transport=transport))
        findings = evaluate(policy, result, datetime(2026, 8, 26, tzinfo=UTC))

        self.assertEqual(len(result.repositories), 1)
        self.assertNotIn(nested_path, result.repositories[0].workflow_sources)
        self.assertIn(
            "WORKFLOW_BASELINE_MISSING", {finding.code for finding in findings}
        )

    def test_non_blob_dependabot_path_cannot_satisfy_the_baseline(self) -> None:
        transport = repository_tree_transport(
            [
                {
                    "path": ".github/workflows/verify.yml",
                    "type": "blob",
                    "sha": blob_sha(WORKFLOW),
                },
                {
                    "path": ".github/dependabot.yml",
                    "type": "tree",
                    "sha": "dependabot-tree-sha",
                },
            ]
        )
        policy = replace(small_policy(), expected_repositories=("example",))

        result = collect_estate(policy, GitHubClient("token", transport=transport))
        findings = evaluate(policy, result, datetime(2026, 8, 26, tzinfo=UTC))

        self.assertEqual(len(result.repositories), 1)
        self.assertNotIn(".github/dependabot.yml", result.repositories[0].paths)
        self.assertIn(
            "DEPENDABOT_BASELINE_MISSING", {finding.code for finding in findings}
        )

    def test_only_workflows_with_runs_of_their_own_are_looked_up_by_name(self) -> None:
        for raw, looked_up in (
            (b"name: Shared\non:\n  workflow_call:\njobs: {}\n", False),
            (b"name: Manual\non: workflow_dispatch\njobs: {}\n", True),
        ):
            with self.subTest(raw=raw):
                transport = repository_tree_transport(
                    [
                        {"path": ".github/workflows/w.yml", "type": "blob", "sha": blob_sha(raw)},
                        {"path": ".github/dependabot.yml", "type": "blob", "sha": "dependabot-sha"},
                    ],
                    raw=raw,
                )
                policy = replace(small_policy(), expected_repositories=("example",))

                result = collect_estate(policy, GitHubClient("token", transport=transport))
                findings = evaluate(policy, result, datetime(2026, 8, 26, tzinfo=UTC))

                self.assertEqual(result.problems, ())
                self.assertEqual(
                    any("/actions/workflows/w.yml/runs?" in url for url, _ in transport.requests),
                    looked_up,
                )
                self.assertNotIn("WORKFLOW_NO_RECENT_RUN", {finding.code for finding in findings})

    def test_workflow_unknown_to_github_by_name_has_no_run(self) -> None:
        # GitHub can keep a renamed workflow under its old filename and answer 404 for the new one.
        raw = b"name: Weekly\non:\n  schedule:\n    - cron: '0 0 * * 1'\njobs: {}\n"
        transport = repository_tree_transport(
            [
                {"path": ".github/workflows/w.yml", "type": "blob", "sha": blob_sha(raw)},
                {"path": ".github/dependabot.yml", "type": "blob", "sha": "dependabot-sha"},
            ],
            raw=raw,
            workflow_lookup=HttpResponse(404, {}, b'{"message": "Not Found"}'),
        )
        policy = replace(small_policy(), expected_repositories=("example",))

        result = collect_estate(policy, GitHubClient("token", transport=transport))
        findings = evaluate(policy, result, datetime(2026, 8, 26, tzinfo=UTC))

        self.assertEqual(result.problems, ())
        self.assertEqual(len(result.repositories), 1)
        self.assertIn("WORKFLOW_NO_RECENT_RUN", {finding.code for finding in findings})


def workflow_run(
    run_id: int, *, path: str = ".github/workflows/release.yml",
    branch: str = "v0.1.5", conclusion: str = "success", event: str = "push",
    created: str = "2026-09-02T13:40:03Z",
) -> dict[str, object]:
    return {
        "id": run_id, "path": path, "head_branch": branch,
        "head_sha": "a" * 40, "conclusion": conclusion, "event": event,
        "status": "completed", "created_at": created,
        "head_repository": {"full_name": "ryanduguid/example"},
    }


class TaggedReleaseCollectorTests(unittest.TestCase):
    def audit(
        self, release_runs: list[dict[str, object]], *, prefix: str = "v",
        main_runs: list[dict[str, object]] | None = None,
        tags: list[dict[str, object]] | None = None,
        heads: object = (), tag_response: HttpResponse | None = None,
        extra_tag_response: HttpResponse | None = None,
        configured: bool = True, remaining: int = 4999,
        older_runs: tuple[dict[str, object], ...] = (),
    ) -> tuple[AuditReport, FakeTransport]:
        if main_runs is None:
            main_runs = [workflow_run(
                10, branch="main", conclusion="failure", created="2026-09-02T13:38:57Z",
            )]
        if tags is None:
            tags = [{"name": prefix + "0.1.5", "commit": {"sha": "a" * 40}}]
        if heads == ():
            heads = []
        lookup_runs = [*main_runs, *older_runs]
        source = b"name: Release\non:\n  push:\n    tags: ['v*']\njobs: {}\n"
        tree = [
            {"path": path, "type": "blob", "sha": blob_sha(source)}
            for path in (".github/workflows/release.yml", ".github/workflows/ci.yml", ".github/dependabot.yml")
        ]

        class RoutingTransport(FakeTransport):
            def __init__(self) -> None:
                super().__init__([])

            def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
                self.requests.append((url, headers))
                parsed = urlsplit(url)
                query = parse_qs(parsed.query)
                base = "/repos/ryanduguid/example"
                if parsed.path == "/users/ryanduguid/repos":
                    return api_response([public_repo()], remaining=remaining)
                if parsed.path == base + "/git/trees/main":
                    return api_response({"truncated": False, "tree": tree})
                if parsed.hostname == "raw.githubusercontent.com":
                    return HttpResponse(200, {}, source)
                if parsed.path == base + "/actions/runs":
                    if query != {"branch": ["main"], "status": ["completed"], "per_page": ["100"]}:
                        raise AssertionError("default-branch query changed")
                    return api_response({"workflow_runs": main_runs})
                if parsed.path.startswith(base + "/actions/workflows/") and query.get("branch") == ["main"]:
                    # A workflow missing from the latest runs is looked up by name;
                    # older_runs fell out of the latest 100.
                    if set(query) != {"branch", "status", "per_page"} or query["status"] != ["completed"]:
                        raise AssertionError("workflow lookup query changed")
                    name = parsed.path.removeprefix(base + "/actions/workflows/").removesuffix("/runs")
                    own = [run for run in lookup_runs if run["path"] == ".github/workflows/" + name]
                    return api_response({"workflow_runs": own[:int(query["per_page"][0])]})
                if parsed.path == base + "/actions/workflows/release.yml/runs":
                    if query != {"status": ["completed"], "per_page": ["100"]}:
                        raise AssertionError("tagged workflow query changed")
                    return api_response({"workflow_runs": release_runs})
                if parsed.path == base + "/tags":
                    if query.get("page") == ["2"] and extra_tag_response is not None:
                        return extra_tag_response
                    return tag_response if tag_response is not None else api_response(tags)
                if parsed.path.startswith(base + "/git/matching-refs/heads/"):
                    return api_response(heads)
                if parsed.path == base + "/pulls":
                    return api_response([])
                raise AssertionError(f"unexpected request: {url}")

        transport = RoutingTransport()
        policy = replace(
            small_policy(), expected_repositories=("example",),
            tagged_release_workflows={"example": {"release.yml": prefix}} if configured else {},
        )
        result = collect_estate(policy, GitHubClient("TOKEN-SENTINEL", transport=transport))
        now = datetime(2026, 9, 3, tzinfo=UTC)
        report = build_report(policy, result, evaluate(policy, result, now), now, now)
        return report, transport

    def test_verified_root_and_namespaced_tag_supersede_old_main_failure(self) -> None:
        for prefix, event in (("v", "push"), ("example/v", "workflow_dispatch")):
            with self.subTest(prefix=prefix):
                report, transport = self.audit([workflow_run(20, branch=prefix + "0.1.5", event=event)], prefix=prefix)
                self.assertEqual(report.status, AuditStatus.ALL_CLEAR)
                self.assertEqual(report.collection_errors, ())
                self.assertTrue(any("/actions/workflows/release.yml/runs?" in url for url, _ in transport.requests))

    def test_new_failed_tag_is_not_hidden_by_older_success_or_response_order(self) -> None:
        # A rerun may update an old run without making its source the latest release.
        older = {**workflow_run(99, created="2026-09-02T13:39:00Z"), "updated_at": "2026-09-03T13:00:00Z"}
        latest = workflow_run(20, conclusion="failure")
        report, _ = self.audit([older, latest])
        failures = [item for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"]
        self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
        self.assertEqual([item.url for item in failures], ["https://github.com/ryanduguid/example/actions/runs/20"])

    def test_failure_outside_the_latest_runs_is_found_by_workflow_name(self) -> None:
        ci = ".github/workflows/ci.yml"
        report, transport = self.audit(
            [workflow_run(20)], main_runs=[],
            older_runs=(workflow_run(5, path=ci, branch="main", conclusion="failure"),),
        )
        failures = [item for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"]
        lookups = [url for url, _ in transport.requests if "/actions/workflows/" in url and "branch=main" in url]
        self.assertEqual([item.url for item in failures], ["https://github.com/ryanduguid/example/actions/runs/5"])
        self.assertEqual(len(lookups), 1)
        self.assertIn("/actions/workflows/ci.yml/runs?branch=main&", lookups[0])

    def test_lookup_passes_pull_request_runs_to_reach_an_older_failure(self) -> None:
        ci = ".github/workflows/ci.yml"
        report, _ = self.audit(
            [workflow_run(20)], main_runs=[],
            older_runs=(
                workflow_run(6, path=ci, branch="main", event="pull_request", created="2026-09-02T13:00:00Z"),
                workflow_run(5, path=ci, branch="main", conclusion="failure", created="2026-09-01T13:00:00Z"),
            ),
        )
        failures = [item for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"]
        self.assertEqual([item.url for item in failures], ["https://github.com/ryanduguid/example/actions/runs/5"])

    def test_new_main_failure_is_not_hidden_by_older_tag_success(self) -> None:
        report, _ = self.audit(
            [workflow_run(20)],
            main_runs=[workflow_run(30, branch="main", conclusion="failure", created="2026-09-02T14:00:00Z")],
        )
        failures = [item for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"]
        self.assertEqual([item.url for item in failures], ["https://github.com/ryanduguid/example/actions/runs/30"])

    def test_new_tag_failure_is_not_hidden_by_a_different_successful_tag(self) -> None:
        latest = {**workflow_run(30, branch="v0.2.0", conclusion="failure"), "head_sha": "b" * 40}
        report, _ = self.audit(
            [workflow_run(20, created="2026-09-02T13:39:00Z"), latest],
            tags=[
                {"name": "v0.1.5", "commit": {"sha": "a" * 40}},
                {"name": "v0.2.0", "commit": {"sha": "b" * 40}},
            ],
        )
        failures = [item for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"]
        self.assertEqual(report.collection_errors, ())
        self.assertEqual([item.url for item in failures], ["https://github.com/ryanduguid/example/actions/runs/30"])

    def test_pr_feature_and_release_successes_cannot_mask_failed_main_ci(self) -> None:
        ci = ".github/workflows/ci.yml"
        main_runs = [
            workflow_run(90, path=ci, branch="feature/green"),
            workflow_run(80, path=ci, branch="main", event="pull_request"),
            workflow_run(70, path=ci, branch="main", event="pull_request_target"),
            workflow_run(60, path=ci, branch="main", conclusion="failure"),
        ]
        report, _ = self.audit([workflow_run(100)], main_runs=main_runs)
        failures = [item for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"]
        self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
        self.assertEqual([item.url for item in failures], ["https://github.com/ryanduguid/example/actions/runs/60"])

    def test_unrelated_namespace_feature_and_pr_runs_do_not_supersede_failure(self) -> None:
        for branch, event in (("other/v0.1.5", "push"), ("feature/fix", "push"), ("v0.1.5", "pull_request"), ("v0.1.5", "pull_request_target"), ("v0.1.5", "merge_group")):
            with self.subTest(branch=branch, event=event):
                report, _ = self.audit([workflow_run(20, branch=branch, event=event)])
                self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
                self.assertEqual([item.url for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"], ["https://github.com/ryanduguid/example/actions/runs/10"])

    def test_null_branch_on_ignored_events_does_not_block_tag_evidence(self) -> None:
        for event in ("pull_request", "pull_request_target", "merge_group", "workflow_run"):
            with self.subTest(event=event):
                ignored = {**workflow_run(30, event=event), "head_branch": None}
                report, _ = self.audit([ignored, workflow_run(20)])
                self.assertEqual(report.collection_errors, ())
                self.assertEqual(report.status, AuditStatus.ALL_CLEAR)

    def test_null_branch_pr_events_do_not_hide_failed_main_ci(self) -> None:
        ci = ".github/workflows/ci.yml"
        for event in ("pull_request", "pull_request_target", "merge_group"):
            with self.subTest(event=event):
                ignored = {**workflow_run(30, path=ci, event=event), "head_branch": None}
                failed = workflow_run(10, path=ci, branch="main", conclusion="failure")
                report, _ = self.audit([workflow_run(20)], main_runs=[ignored, failed])
                self.assertEqual(report.collection_errors, ())
                self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
                failures = [item for item in report.findings if item.code == "WORKFLOW_RUN_FAILED"]
                self.assertEqual([item.url for item in failures], ["https://github.com/ryanduguid/example/actions/runs/10"])

    def test_missing_moved_or_ambiguous_tag_evidence_makes_report_incomplete(self) -> None:
        cases: tuple[dict[str, Any], ...] = (
            {"tags": []},
            {"tags": [{"name": "v0.1.5", "commit": {"sha": "b" * 40}}]},
            {"tags": [{"name": "v0.1.5", "commit": {"sha": "not-a-sha"}}]},
            {"heads": [{"ref": "refs/heads/v0.1.5"}]},
            {"heads": {}},
            {"heads": [{}]},
            {"tag_response": HttpResponse(403, api_response({}).headers, b"{}")},
        )
        for options in cases:
            with self.subTest(options=options):
                report, _ = self.audit([workflow_run(20)], **options)
                self.assertEqual(report.status, AuditStatus.INCOMPLETE)
                self.assertTrue(report.collection_errors)
                self.assertNotIn("TOKEN-SENTINEL", render_json(report) + render_text(report))

    def test_malformed_or_foreign_release_run_cannot_supply_green_evidence(self) -> None:
        changes: tuple[dict[str, object], ...] = (
            {"head_sha": "not-a-sha"}, {"created_at": "not-a-time"},
            {"status": "in_progress"}, {"created_at": "2026-09-02T13:40:03"},
            {"head_branch": None}, {"event": []},
            {"head_repository": {"full_name": "someone-else/example"}},
            {"path": ".github/workflows/ci.yml"},
        )
        for change in changes:
            with self.subTest(change=change):
                report, _ = self.audit([{**workflow_run(20), **change}])
                self.assertEqual(report.status, AuditStatus.INCOMPLETE)

    def test_a_run_whose_tag_was_deleted_matters_only_while_it_is_the_latest_attempt(self) -> None:
        deleted = {**workflow_run(15, conclusion="failure", created="2026-09-02T13:39:00Z"), "head_branch": None}
        report, _ = self.audit([deleted, workflow_run(20)])
        self.assertEqual(report.collection_errors, ())
        self.assertEqual(report.status, AuditStatus.ALL_CLEAR)
        newer = {**deleted, "id": 25, "created_at": "2026-09-02T13:41:00Z"}
        report, _ = self.audit([newer, workflow_run(20)])
        self.assertEqual(report.status, AuditStatus.INCOMPLETE)

    def test_latest_cancelled_release_remains_a_notice(self) -> None:
        report, _ = self.audit([workflow_run(20, conclusion="cancelled")])
        self.assertEqual(report.status, AuditStatus.ALL_CLEAR)
        notices = [item for item in report.findings if item.code == "WORKFLOW_RUN_NOTICE"]
        self.assertEqual([item.url for item in notices], ["https://github.com/ryanduguid/example/actions/runs/20"])

    def test_unconfigured_workflow_keeps_default_branch_policy(self) -> None:
        report, transport = self.audit([workflow_run(20)], configured=False)
        self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
        # Only default-branch lookups: no tag listing and no tagged-release run query.
        self.assertFalse(any(
            "/tags" in url or ("/actions/workflows/" in url and "branch=main" not in url)
            for url, _ in transport.requests
        ))

    def test_minimum_reserved_capacity_allows_collection(self) -> None:
        # One configured workflow adds its run query, up to 10 tag pages and
        # branch disambiguation to the 3 existing repository requests.
        for configured, remaining in ((True, 115), (False, 103)):
            with self.subTest(configured=configured):
                report, _ = self.audit([workflow_run(20)], configured=configured, remaining=remaining)
                self.assertEqual(report.collection_errors, ())
                self.assertEqual(report.status, AuditStatus.ALL_CLEAR if configured else AuditStatus.ACTION_REQUIRED)

    def test_tag_lookup_follows_bounded_pagination(self) -> None:
        report, _ = self.audit(
            [workflow_run(20)],
            tag_response=api_response([], link='<https://api.github.com/repos/ryanduguid/example/tags?page=2>; rel="next"'),
            extra_tag_response=api_response([{"name": "v0.1.5", "commit": {"sha": "a" * 40}}]),
        )
        self.assertEqual(report.status, AuditStatus.ALL_CLEAR)

    def test_version_suffix_accepts_prereleases_and_builds_without_crossing_namespaces(self) -> None:
        for tag in ("example/v0.2.0-rc.1", "example/v0.2.0-rc.1+build.7"):
            with self.subTest(tag=tag):
                report, _ = self.audit(
                    [workflow_run(20, branch=tag)], prefix="example/v",
                    tags=[{"name": tag, "commit": {"sha": "a" * 40}}],
                )
                self.assertEqual(report.status, AuditStatus.ALL_CLEAR)

    def test_unknown_configured_workflow_makes_collection_incomplete(self) -> None:
        policy = replace(small_policy(), expected_repositories=("example",), tagged_release_workflows={"example": {"release.yml": "v"}})
        result = collect_estate(policy, GitHubClient("token", transport=collection_transport()))
        self.assertTrue(result.problems)


def package_commit(sha: str, when: str) -> dict[str, object]:
    return {"sha": sha, "commit": {"committer": {"date": when}, "message": "SENSITIVE-COMMIT-SENTINEL"}}


class ReleaseQueueCollectorTests(unittest.TestCase):
    """The queue flags an untagged version and package changes that have waited too long for a release."""

    TAG_SHA = "b" * 40
    FILES = {
        "pyproject.toml": '[project]\nname = "example"\nversion = "0.1.10"\n',
        "VERSION": "0.1.10\n",
        "pkg/version.py": '"""Version."""\n\n__version__ = "0.1.10"\n',
    }

    def audit(
        self, commits: dict[str, list[dict[str, object]]], *,
        tags: list[dict[str, object]] | None = None,
        release_runs: list[dict[str, object]] | None = None,
        paths: tuple[str, ...] = ("pkg", "pyproject.toml"),
        version_file: str = "pyproject.toml",
        files: dict[str, str] | None = None,
        deferrals: dict[str, dict[str, ReleaseDeferral]] | None = None,
        tag_commit: object = None,
        now: datetime = datetime(2026, 9, 20, tzinfo=UTC),
    ) -> tuple[AuditReport, FakeTransport]:
        if tags is None:
            tags = [
                {"name": "v0.1.9", "commit": {"sha": "a" * 40}},
                {"name": "v0.1.10", "commit": {"sha": self.TAG_SHA}},
                {"name": "other/v9.9.9", "commit": {"sha": "c" * 40}},
            ]
        if release_runs is None:
            release_runs = [{**workflow_run(20, branch="v0.1.10"), "head_sha": self.TAG_SHA}]
        if tag_commit is None:
            tag_commit = {"sha": self.TAG_SHA, "committer": {"date": "2026-09-10T00:00:00Z"}}
        contents = {**self.FILES, **(files or {})}
        source = b"name: Release\non:\n  push:\n    tags: ['v*']\njobs: {}\n"
        tree = [
            {"path": path, "type": "blob", "sha": blob_sha(source)}
            for path in (".github/workflows/release.yml", ".github/dependabot.yml")
        ] + [
            {"path": path, "type": "blob", "sha": "f" * 40}
            for path in ("pkg/module.py", "docs/guide.md", *self.FILES)
        ]

        class RoutingTransport(FakeTransport):
            def __init__(self) -> None:
                super().__init__([])

            def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
                self.requests.append((url, headers))
                parsed = urlsplit(url)
                query = parse_qs(parsed.query)
                base = "/repos/ryanduguid/example"
                if parsed.path == "/users/ryanduguid/repos":
                    return api_response([public_repo()])
                if parsed.path == base + "/git/trees/main":
                    return api_response({"truncated": False, "tree": tree})
                if parsed.hostname == "raw.githubusercontent.com":
                    return HttpResponse(200, {}, source)
                if parsed.path == base + "/actions/runs":
                    return api_response({"workflow_runs": []})
                if parsed.path == base + "/actions/workflows/release.yml/runs":
                    return api_response({"workflow_runs": release_runs})
                if parsed.path == base + "/tags":
                    return api_response(tags)
                if parsed.path.startswith(base + "/git/matching-refs/heads/"):
                    return api_response([])
                if parsed.path == base + "/git/commits/" + ReleaseQueueCollectorTests.TAG_SHA:
                    return api_response(tag_commit)
                if parsed.path.startswith(base + "/contents/"):
                    if query != {"ref": ["main"]}:
                        raise AssertionError("version file query changed")
                    text = contents[parsed.path.removeprefix(base + "/contents/")]
                    return api_response({"encoding": "base64", "content": base64.b64encode(text.encode()).decode()})
                if parsed.path == base + "/commits":
                    expected = {"sha": ["main"], "since": ["2026-09-10T00:00:00Z"], "per_page": ["100"]}
                    if {key: value for key, value in query.items() if key != "path"} != expected:
                        raise AssertionError("package commit query changed")
                    return api_response(commits.get(query["path"][0], []))
                if parsed.path == base + "/pulls":
                    return api_response([])
                raise AssertionError(f"unexpected request: {url}")

        transport = RoutingTransport()
        policy = replace(
            small_policy(), expected_repositories=("example",),
            tagged_release_workflows={"example": {"release.yml": "v"}},
            release_components={"example": {"release.yml": ReleaseComponent(paths, version_file)}},
            release_deferrals=deferrals or {},
        )
        result = collect_estate(policy, GitHubClient("TOKEN-SENTINEL", transport=transport))
        return build_report(policy, result, evaluate(policy, result, now), now, now), transport

    @staticmethod
    def queue_findings(report: AuditReport) -> list[tuple[Severity, str, str, str]]:
        return [
            (item.severity, item.code, item.summary, item.url) for item in report.findings
            if item.code.startswith("RELEASE_")
        ]

    def test_package_changes_waiting_past_the_limit_are_flagged_from_the_latest_version(self) -> None:
        report, transport = self.audit({"pkg": [
            package_commit("d" * 40, "2026-09-15T00:00:00Z"),
            package_commit("e" * 40, "2026-09-11T00:00:00Z"),
            package_commit(self.TAG_SHA, "2026-09-10T00:00:00Z"),
        ]})
        self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
        self.assertEqual(self.queue_findings(report), [(
            Severity.ACTION, "RELEASE_CHANGES_UNRELEASED",
            "package changes since v0.1.10 have waited more than 7 days for a release",
            f"https://github.com/ryanduguid/example/compare/{self.TAG_SHA}...main",
        )])
        queried = sorted(parse_qs(urlsplit(url).query)["path"][0] for url, _ in transport.requests if "/commits?" in url)
        self.assertEqual(queried, ["pkg", "pyproject.toml"])
        self.assertNotIn("SENSITIVE-COMMIT-SENTINEL", render_json(report) + render_text(report))

    def test_a_version_on_main_without_its_tag_is_flagged_at_once(self) -> None:
        # The roadmap's fixture: 0.1.8 on main with tags up to 0.1.7, bumped a day ago.
        tags: list[dict[str, object]] = [{"name": "v0.1.7", "commit": {"sha": self.TAG_SHA}}]
        runs = [{**workflow_run(20, branch="v0.1.7"), "head_sha": self.TAG_SHA}]
        for version_file, text in (
            ("pyproject.toml", '[project]\nname = "example"\nversion = "0.1.8"\n'),
            ("VERSION", "0.1.8\n"),
            ("pkg/version.py", '__version__ = "0.1.8"\n'),
            ("pkg/version.py", '\ufeff# Package release version\n__version__ = "0.1.8"\n'),
            ("pkg/version.py", '__version__ = "0.1.8"  # Package release version\n'),
            ("pkg/version.py", '__version__: str = "0.1.8"\n'),
            ("pkg/version.py", '(__version__): str = "0.1.8"\n'),
            ("pkg/version.py", '"""Example:\n__version__ = "0.1.7"\n"""\n__version__ = "0.1.8"\n'),
        ):
            with self.subTest(version_file=version_file, source=text):
                report, _ = self.audit(
                    {"pyproject.toml": [package_commit("d" * 40, "2026-09-19T00:00:00Z")]},
                    tags=tags, release_runs=runs, version_file=version_file, files={version_file: text},
                )
                self.assertEqual(self.queue_findings(report), [(
                    Severity.ACTION, "RELEASE_VERSION_UNTAGGED",
                    "version 0.1.8 has no release tag; the latest is v0.1.7",
                    f"https://github.com/ryanduguid/example/blob/main/{version_file}",
                )])

    def test_documentation_only_recent_or_released_changes_are_not_flagged(self) -> None:
        # The package-path queries return nothing for a documentation-only change.
        for commits in (
            {},
            {"pkg": [package_commit(self.TAG_SHA, "2026-09-10T00:00:00Z")]},
            {"pkg": [package_commit("d" * 40, "2026-09-13T00:00:01Z")]},
        ):
            with self.subTest(commits=commits):
                report, _ = self.audit(commits)
                self.assertEqual(report.status, AuditStatus.ALL_CLEAR)
                self.assertEqual(self.queue_findings(report), [])

    def test_unsupported_python_version_evidence_makes_the_report_incomplete(self) -> None:
        literal = '__version__ = "0.1.10"\n'
        for source in (
            '"""Example:\n' + literal + '"""\n',
            '__version__ = calculate_version()\n',
            '__version__: str\n',
            '__version__ = other = "0.1.10"\n',
            literal + 'invalid Python syntax\n',
            literal + 'return\n',
            literal + '__version__ = "0.2.0"\n',
            literal + '__version__ = calculate_version()\n',
            literal + 'if condition:\n    __version__ = "0.2.0"\n',
            literal + '__version__ += ".1"\n',
            literal + 'del __version__\n',
            literal + 'def __version__():\n    return "0.2.0"\n',
            literal + 'def function(__version__):\n    pass\n',
            literal + 'function = lambda __version__: None\n',
            literal + 'def function[__version__]():\n    pass\n',
            literal + 'def function[*__version__]():\n    pass\n',
            literal + 'def function[**__version__]():\n    pass\n',
            literal + 'from package import current as __version__\n',
            literal + 'try:\n    pass\nexcept Exception as __version__:\n    pass\n',
            literal + 'match value:\n    case {**__version__}:\n        pass\n',
        ):
            with self.subTest(source=source):
                report, _ = self.audit(
                    {}, version_file="pkg/version.py", files={"pkg/version.py": source},
                )
                self.assertEqual(report.status, AuditStatus.INCOMPLETE)
                self.assertEqual([item.code for item in report.collection_errors],
                                 ["GITHUB_RESPONSE_INVALID"])

    def test_a_change_one_second_past_the_limit_is_flagged(self) -> None:
        report, _ = self.audit({"pkg": [package_commit("d" * 40, "2026-09-12T23:59:59Z")]})
        self.assertEqual([item[1] for item in self.queue_findings(report)], ["RELEASE_CHANGES_UNRELEASED"])

    def test_a_deferral_holds_until_its_review_date(self) -> None:
        waiting = {"pkg": [package_commit("d" * 40, "2026-09-11T00:00:00Z")]}
        bumped = {"VERSION": "0.2.0\n"}
        for review_by, codes in (
            (date(2026, 9, 20), []),
            (date(2026, 9, 19), ["RELEASE_CHANGES_UNRELEASED", "RELEASE_VERSION_UNTAGGED"]),
        ):
            with self.subTest(review_by=review_by):
                deferral = ReleaseDeferral("waiting on the v1 schema", review_by)
                report, _ = self.audit(
                    waiting, version_file="VERSION", files=bumped,
                    deferrals={"example": {"release.yml": deferral}},
                )
                self.assertEqual(sorted(item[1] for item in self.queue_findings(report)), codes)

    def test_a_component_without_a_release_tag_is_a_notice(self) -> None:
        report, transport = self.audit(
            {}, tags=[{"name": "other/v9.9.9", "commit": {"sha": "c" * 40}}], release_runs=[],
        )
        self.assertEqual(report.collection_errors, ())
        self.assertEqual(self.queue_findings(report), [(
            Severity.NOTICE, "RELEASE_TAG_MISSING", "release.yml has no release tag matching its prefix",
            "https://github.com/ryanduguid/example/blob/main/.github/workflows/release.yml",
        )])
        self.assertFalse(any("/commits" in url for url, _ in transport.requests))

    def test_a_missing_path_or_malformed_version_or_commit_makes_the_report_incomplete(self) -> None:
        missing: tuple[dict[str, Any], ...] = ({"paths": ("pkg", "src")}, {"version_file": "pkg/missing.py"})
        for options in missing:
            with self.subTest(options=options):
                report, transport = self.audit({}, **options)
                self.assertEqual([problem.code for problem in report.collection_errors], ["RELEASE_PATH_MISSING"])
                self.assertFalse(any("/contents/" in url for url, _ in transport.requests))
        cases: tuple[dict[str, Any], ...] = (
            {"files": {"pyproject.toml": '[project]\nname = "example"\ndynamic = ["version"]\n'}},
            {"files": {"pyproject.toml": "[project\n"}},
            {"version_file": "VERSION", "files": {"VERSION": "latest\n"}},
            {"version_file": "pkg/version.py", "files": {"pkg/version.py": "VERSION = '0.1.10'\n"}},
            {"commits": {"pkg": [package_commit("not-a-sha", "2026-09-15T00:00:00Z")]}},
            {"commits": {"pkg": [{"sha": "d" * 40, "commit": {}}]}},
            {"commits": {"pkg": [package_commit("d" * 40, "not-a-time")]}},
            {"tag_commit": {"sha": self.TAG_SHA}},
            {"tag_commit": {"committer": "2026-09-10T00:00:00Z"}},
            {"tag_commit": []},
        )
        for options in cases:
            with self.subTest(options=options):
                report, _ = self.audit(options.pop("commits", {}), **options)
                self.assertEqual(report.status, AuditStatus.INCOMPLETE)
                self.assertTrue(report.collection_errors)


class BlobIntegrityTests(unittest.TestCase):
    def test_git_blob_sha_matches_tree_identity(self) -> None:
        self.assertEqual(git_blob_sha(WORKFLOW), blob_sha(WORKFLOW))

    def test_changed_raw_workflow_records_mismatch(self) -> None:
        client = GitHubClient("token", transport=collection_transport(raw=b"changed"))
        result = collect_estate(load_policy(Path("portfolio-audit-policy.json")), client)
        self.assertIn("RAW_WORKFLOW_MISMATCH", {problem.code for problem in result.problems})


def small_policy() -> Policy:
    return Policy(
        schema_version=1,
        owner="ryanduguid",
        expected_repositories=("expected",),
        workflow_exemptions={},
        dependabot_exemptions={},
        dependabot_max_age_days=14,
        release_policy_pins={
            "release-python.yml": frozenset(
                {"3b8a377207cab2c7c808fcc96b66578f4695beea"}
            )
        },
    )


class WorkflowTriggerTests(unittest.TestCase):
    def test_reads_top_level_trigger_forms(self) -> None:
        cases = (
            ("on:\n  push:\n    branches: [main]\n  schedule:\n    - cron: '0 0 * * 1'\njobs: {}\n", {"push", "schedule"}),
            ("on:\n  - push\n  - workflow_dispatch\n", {"push", "workflow_dispatch"}),
            ("on:\n  - workflow_call # shared\n  - workflow_dispatch  # by hand\n", {"workflow_call", "workflow_dispatch"}),
            ("on: workflow_call # shared\n", {"workflow_call"}),
            ('on: [push, "workflow_dispatch"]\n', {"push", "workflow_dispatch"}),
            ('"on": # triggers\n  # none yet\n  workflow_call:\n    inputs: {}\njobs: {}\n', {"workflow_call"}),
            ("'on' :\n  workflow_dispatch:\n", {"workflow_dispatch"}),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(_workflow_triggers(source), frozenset(expected))

    def test_unreadable_or_missing_triggers_are_none(self) -> None:
        for source in (
            "on: {push: {}}\n",
            "on:\njobs: {}\n",
            "only: push\njobs:\n  a:\n    on: push\n",
            WORKFLOW.decode(),
        ):
            with self.subTest(source=source):
                self.assertIsNone(_workflow_triggers(source))


def snapshot(
    *,
    workflow_source: str = "",
    runs: tuple[WorkflowRun, ...] = (),
    pulls: tuple[DependabotPullRequest, ...] = (),
) -> RepositorySnapshot:
    return RepositorySnapshot(
        name="expected",
        default_branch="main",
        paths=frozenset(
            {".github/workflows/release.yml", ".github/dependabot.yml"}
        ),
        workflow_sources={".github/workflows/release.yml": workflow_source},
        workflow_runs=runs,
        dependabot_pull_requests=pulls,
    )


def collection(
    repository: RepositorySnapshot,
    *,
    problems: tuple[CollectionProblem, ...] = (),
) -> CollectionResult:
    return CollectionResult(
        discovered_repositories=(repository.name,),
        repositories=(repository,),
        problems=problems,
        request_count=4,
        rate_limit={"limit": "5000", "remaining": "4900", "reset": "1"},
    )


class EvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)

    def test_estate_membership_reports_new_and_missing_repositories(self) -> None:
        value = collection(snapshot())
        value = CollectionResult(("new",), value.repositories, (), 4, value.rate_limit)
        codes = {finding.code for finding in evaluate(small_policy(), value, self.now)}
        self.assertEqual(codes, {"UNEXPECTED_REPOSITORY", "EXPECTED_REPOSITORY_MISSING"})

    def test_baselines_report_missing_files_without_exemption(self) -> None:
        repository = snapshot()
        repository = RepositorySnapshot(
            repository.name,
            repository.default_branch,
            frozenset(),
            {},
            (),
            (),
        )
        codes = {finding.code for finding in evaluate(small_policy(), collection(repository), self.now)}
        self.assertIn("WORKFLOW_BASELINE_MISSING", codes)
        self.assertIn("DEPENDABOT_BASELINE_MISSING", codes)

    def test_latest_failed_run_is_action_and_absent_run_is_notice(self) -> None:
        failed = snapshot(runs=(WorkflowRun(42, ".github/workflows/release.yml", "failure"),))
        findings = evaluate(small_policy(), collection(failed), self.now)
        self.assertIn("WORKFLOW_RUN_FAILED", {finding.code for finding in findings})
        absent = evaluate(small_policy(), collection(snapshot()), self.now)
        self.assertIn("WORKFLOW_NO_RECENT_RUN", {finding.code for finding in absent})

    def test_absent_run_notice_skips_workflows_without_runs_of_their_own(self) -> None:
        cases = (
            ("on:\n  workflow_call:\n", False),
            ("on: [workflow_call, workflow_dispatch]\n", False),
            ("on:\n  schedule:\n    - cron: '0 0 * * 1'\n  workflow_dispatch:\n", True),
            ("name: Unreadable\non: {push: {}}\n", True),
        )
        for source, notice in cases:
            with self.subTest(source=source):
                findings = evaluate(small_policy(), collection(snapshot(workflow_source=source)), self.now)
                self.assertEqual("WORKFLOW_NO_RECENT_RUN" in {item.code for item in findings}, notice)

    def test_manual_only_workflow_failure_is_still_reported(self) -> None:
        failed = snapshot(
            workflow_source="on: workflow_dispatch\n",
            runs=(WorkflowRun(42, ".github/workflows/release.yml", "failure"),),
        )
        findings = evaluate(small_policy(), collection(failed), self.now)
        self.assertIn("WORKFLOW_RUN_FAILED", {finding.code for finding in findings})

    def test_dependabot_age_is_strictly_greater_than_fourteen_days(self) -> None:
        boundary = DependabotPullRequest(7, self.now - timedelta(days=14))
        stale = DependabotPullRequest(8, self.now - timedelta(days=14, seconds=1))
        findings = evaluate(
            small_policy(),
            collection(snapshot(pulls=(boundary, stale))),
            self.now,
        )
        stale_urls = [finding.url for finding in findings if finding.code == "DEPENDABOT_PR_STALE"]
        self.assertEqual(stale_urls, ["https://github.com/ryanduguid/expected/pull/8"])

    def test_pin_malformed_and_unapproved_are_distinct(self) -> None:
        malformed = "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml@main\n"
        unapproved = "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml@47480b782926179b621ec1c6643ef88c80fc8fd4\n"
        malformed_codes = {finding.code for finding in evaluate(small_policy(), collection(snapshot(workflow_source=malformed)), self.now)}
        unapproved_codes = {finding.code for finding in evaluate(small_policy(), collection(snapshot(workflow_source=unapproved)), self.now)}
        self.assertIn("RELEASE_POLICY_PIN_MALFORMED", malformed_codes)
        self.assertIn("RELEASE_POLICY_PIN_UNAPPROVED", unapproved_codes)

    def test_release_policy_does_not_audit_its_own_signer_identity_as_a_consumer_pin(self) -> None:
        repository = RepositorySnapshot(
            name="release-policy",
            default_branch="main",
            paths=frozenset(
                {".github/workflows/release-python.yml", ".github/dependabot.yml"}
            ),
            workflow_sources={
                ".github/workflows/release-python.yml": (
                    'signer="ryanduguid/release-policy/.github/workflows/'
                    'release-python.yml"\n'
                )
            },
            workflow_runs=(),
            dependabot_pull_requests=(),
        )
        findings = evaluate(
            small_policy(),
            CollectionResult(
                discovered_repositories=("release-policy",),
                repositories=(repository,),
                problems=(),
                request_count=1,
                rate_limit={},
            ),
            self.now,
        )
        self.assertEqual(
            [
                finding.code
                for finding in findings
                if finding.code.startswith("RELEASE_POLICY_PIN_")
            ],
            [],
        )

    def test_consumer_attestation_signer_identity_is_not_a_malformed_pin(self) -> None:
        # A consumer that calls a pinned release-policy workflow and then
        # verifies the resulting attestations names the signing workflow by
        # path. That argument takes no @<sha>: the commit is pinned by
        # --signer-digest, so it must not read as an unpinned reference.
        approved = "3b8a377207cab2c7c808fcc96b66578f4695beea"
        source = (
            "jobs:\n"
            "  release:\n"
            "    uses: ryanduguid/release-policy/.github/workflows/"
            f"release-python.yml@{approved}\n"
            "  prove:\n"
            "    steps:\n"
            "      - run: |\n"
            '          gh attestation verify "$wheel" --repo "$repo" \\\n'
            "            --signer-workflow ryanduguid/release-policy/"
            ".github/workflows/release-python.yml \\\n"
            '            --signer-digest "$policy"\n'
            '          gh attestation verify "$sbom" --repo "$repo" \\\n'
            "            --signer-workflow ryanduguid/release-policy/"
            ".github/workflows/release-python.yml \\\n"
            '            --signer-digest "$policy"\n'
        )
        codes = {
            finding.code
            for finding in evaluate(
                small_policy(),
                collection(snapshot(workflow_source=source)),
                self.now,
            )
        }
        self.assertNotIn("RELEASE_POLICY_PIN_MALFORMED", codes)
        self.assertNotIn("RELEASE_POLICY_PIN_UNAPPROVED", codes)

    def test_signer_identity_without_a_signer_digest_is_malformed(self) -> None:
        # Nothing pins the signer commit here, so the reference stays
        # unconsumed and the check fails closed.
        approved = "3b8a377207cab2c7c808fcc96b66578f4695beea"
        source = (
            "jobs:\n"
            "  release:\n"
            "    uses: ryanduguid/release-policy/.github/workflows/"
            f"release-python.yml@{approved}\n"
            "  prove:\n"
            "    steps:\n"
            '      - run: gh attestation verify "$wheel" --signer-workflow '
            "ryanduguid/release-policy/.github/workflows/release-python.yml\n"
        )
        codes = {
            finding.code
            for finding in evaluate(
                small_policy(),
                collection(snapshot(workflow_source=source)),
                self.now,
            )
        }
        self.assertIn("RELEASE_POLICY_PIN_MALFORMED", codes)

    def test_signer_identity_argument_forms(self) -> None:
        workflow = "ryanduguid/release-policy/.github/workflows/release-python.yml"
        digest = "3b8a377207cab2c7c808fcc96b66578f4695beea"
        for arguments in (
            f'--signer-workflow "{workflow}" --signer-digest {digest}',
            f'--signer-workflow={workflow} --signer-digest="$policy"',
            f'--signer-digest "${{policy}}" --signer-workflow {workflow}',
            f'--signer-workflow {workflow} \\\r\n          --signer-digest "$policy"',
            f'--signer-workflow {workflow} --signer-digest "$policy" # checked',
        ):
            with self.subTest(arguments=arguments):
                source = (
                    "jobs:\n  prove:\n    steps:\n"
                    f"      - run: gh attestation verify wheel {arguments}\n"
                )
                codes = {
                    finding.code
                    for finding in evaluate(
                        small_policy(), collection(snapshot(workflow_source=source)), self.now
                    )
                }
                self.assertNotIn("RELEASE_POLICY_PIN_MALFORMED", codes)

    def test_signer_identity_does_not_excuse_an_unpinned_workflow_reference(self) -> None:
        # A valid signer pair must not let a block-scalar `uses:` that the
        # candidate parser cannot read slip through as consumed.
        approved = "3b8a377207cab2c7c808fcc96b66578f4695beea"
        source = (
            "jobs:\n"
            "  release:\n"
            "    uses: >-\n"
            "      ryanduguid/release-policy/.github/workflows/"
            f"release-python.yml@{approved}\n"
            "  prove:\n"
            "    steps:\n"
            "      - run: |\n"
            '          gh attestation verify "$wheel" \\\n'
            "            --signer-workflow ryanduguid/release-policy/"
            ".github/workflows/release-python.yml \\\n"
            '            --signer-digest "$policy"\n'
        )
        codes = {
            finding.code
            for finding in evaluate(
                small_policy(),
                collection(snapshot(workflow_source=source)),
                self.now,
            )
        }
        self.assertIn("RELEASE_POLICY_PIN_MALFORMED", codes)

    def test_signer_identity_needs_its_digest_in_the_same_command(self) -> None:
        # A digest must pin the identity beside it. A commented-out digest, a
        # digest in an unrelated command, one digest covering two identities,
        # and a digest whose value is the next option must all fail closed.
        approved = "3b8a377207cab2c7c808fcc96b66578f4695beea"
        signer = (
            "--signer-workflow ryanduguid/release-policy/"
            ".github/workflows/release-python.yml"
        )
        header = (
            "jobs:\n"
            "  release:\n"
            "    uses: ryanduguid/release-policy/.github/workflows/"
            f"release-python.yml@{approved}\n"
            "  prove:\n"
            "    steps:\n"
            "      - run: |\n"
        )
        unpaired_sources = (
            (
                "quoted separator cannot create a verification command",
                header + f'          echo ";" gh attestation verify "$w" {signer}'
                ' --signer-digest "$policy"\n',
            ),
            (
                "empty digest",
                header + f'          gh attestation verify "$w" {signer}'
                ' --signer-digest ""\n',
            ),
            (
                "missing digest value",
                header + f'          gh attestation verify "$w" {signer} --signer-digest\n',
            ),
            (
                "digest embedded in another argument",
                header + f'          gh attestation verify "$w" {signer}'
                ' --note "--signer-digest $policy"\n',
            ),
            (
                "digest in an inline comment",
                header + f'          gh attestation verify "$w" {signer}'
                ' # --signer-digest "$policy"\n',
            ),
            (
                "digest after a command separator",
                header + f'          gh attestation verify "$w" {signer}'
                ' ; echo --signer-digest "$policy"\n',
            ),
            (
                "digest after a conditional separator",
                header + f'          gh attestation verify "$w" {signer}'
                ' && echo --signer-digest "$policy"\n',
            ),
            (
                "digest in a continued comment",
                header + f'          gh attestation verify "$w" {signer} \\\n'
                '            # --signer-digest "$policy"\n',
            ),
            (
                "escaped workflow suffix",
                header + f'          gh attestation verify "$w" {signer}'
                '\\suffix --signer-digest "$policy"\n',
            ),
            (
                "literal non-digest",
                header + f'          gh attestation verify "$w" {signer}'
                ' --signer-digest garbage\n',
            ),
            (
                "flags on an unrelated command",
                header + f'          echo {signer} --signer-digest "$policy"\n',
            ),
            (
                "two identities with two digests",
                header + f'          gh attestation verify "$w" {signer}'
                f' --signer-digest "$policy" {signer} --signer-digest "$policy"\n',
            ),
            (
                "option after the end-of-options marker",
                header + f'          gh attestation verify "$w" {signer}'
                ' -- --signer-digest "$policy"\n',
            ),
            (
                "digest commented out",
                header + f'          gh attestation verify "$w" {signer}\n'
                '          # --signer-digest "$policy"\n',
            ),
            (
                "digest in an unrelated command",
                header + f'          gh attestation verify "$w" {signer}\n'
                '          printf %s "--signer-digest $policy"\n',
            ),
            (
                "one digest for two identities",
                header + f'          gh attestation verify "$w" {signer} \\\n'
                f"            {signer} \\\n"
                '            --signer-digest "$policy"\n',
            ),
            (
                "digest value is the next option",
                header + f'          gh attestation verify "$w" {signer} \\\n'
                "            --signer-digest --predicate-type spdx\n",
            ),
        )
        for label, source in unpaired_sources:
            with self.subTest(label=label):
                codes = {
                    finding.code
                    for finding in evaluate(
                        small_policy(),
                        collection(snapshot(workflow_source=source)),
                        self.now,
                    )
                }
                self.assertIn("RELEASE_POLICY_PIN_MALFORMED", codes)

    def test_release_policy_candidate_parser_catches_missing_at_and_trailing_content(self) -> None:
        malformed_sources = (
            "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml\n",
            "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml@3b8a377207cab2c7c808fcc96b66578f4695beea trailing\n",
        )
        for source in malformed_sources:
            with self.subTest(source=source):
                codes = {
                    finding.code
                    for finding in evaluate(
                        small_policy(),
                        collection(snapshot(workflow_source=source)),
                        self.now,
                    )
                }
                self.assertIn("RELEASE_POLICY_PIN_MALFORMED", codes)

    def test_release_policy_candidate_parser_accepts_yaml_key_spacing(self) -> None:
        source = "jobs:\n  release:\n    uses : 'ryanduguid/release-policy/.github/workflows/release-python.yml@3b8a377207cab2c7c808fcc96b66578f4695beea' # reviewed\n"
        codes = {
            finding.code
            for finding in evaluate(
                small_policy(),
                collection(snapshot(workflow_source=source)),
                self.now,
            )
        }
        self.assertNotIn("RELEASE_POLICY_PIN_MALFORMED", codes)
        self.assertNotIn("RELEASE_POLICY_PIN_UNAPPROVED", codes)

    def test_non_block_style_release_policy_occurrences_are_malformed(self) -> None:
        approved = "3b8a377207cab2c7c808fcc96b66578f4695beea"
        malformed_sources = (
            (
                "flow mapping",
                "jobs:\n  release: { uses: ryanduguid/release-policy/"
                f".github/workflows/release-python.yml@{approved} }}\n",
            ),
            (
                "block scalar",
                "jobs:\n  release:\n    uses: >-\n      ryanduguid/release-policy/"
                f".github/workflows/release-python.yml@{approved}\n",
            ),
            (
                "alias",
                "release_policy: &release_policy ryanduguid/release-policy/"
                f".github/workflows/release-python.yml@{approved}\n"
                "jobs:\n  release:\n    uses: *release_policy\n",
            ),
            (
                "case-insensitive unconsumed occurrence",
                "# RYANDUGUID/RELEASE-POLICY/.GITHUB/WORKFLOWS/"
                f"RELEASE-PYTHON.YML@{approved}\n",
            ),
        )
        for label, source in malformed_sources:
            with self.subTest(label=label):
                if label != "case-insensitive unconsumed occurrence":
                    self.assertIsInstance(yaml.safe_load(source), dict)
                pin_findings = [
                    finding
                    for finding in evaluate(
                        small_policy(),
                        collection(snapshot(workflow_source=source)),
                        self.now,
                    )
                    if finding.code.startswith("RELEASE_POLICY_PIN_")
                ]
                self.assertEqual(
                    [finding.code for finding in pin_findings],
                    ["RELEASE_POLICY_PIN_MALFORMED"],
                )

    def test_attached_hash_after_approved_sha_is_not_a_yaml_comment(self) -> None:
        source = (
            "jobs:\n  release:\n    uses: ryanduguid/release-policy/"
            ".github/workflows/release-python.yml@"
            "3b8a377207cab2c7c808fcc96b66578f4695beea#junk\n"
        )
        parsed = yaml.safe_load(source)
        self.assertTrue(parsed["jobs"]["release"]["uses"].endswith("#junk"))

        pin_findings = [
            finding
            for finding in evaluate(
                small_policy(), collection(snapshot(workflow_source=source)), self.now
            )
            if finding.code.startswith("RELEASE_POLICY_PIN_")
        ]

        self.assertEqual(
            [finding.code for finding in pin_findings],
            ["RELEASE_POLICY_PIN_MALFORMED"],
        )

    def test_multiple_unconsumed_occurrences_emit_one_source_finding(self) -> None:
        source = (
            "first: ryanduguid/release-policy/.github/workflows/"
            "release-python.yml@main\n"
            "second: ryanduguid/release-policy/.github/workflows/"
            "release-python.yml@main\n"
        )

        pin_findings = [
            finding
            for finding in evaluate(
                small_policy(), collection(snapshot(workflow_source=source)), self.now
            )
            if finding.code.startswith("RELEASE_POLICY_PIN_")
        ]

        self.assertEqual(
            [finding.code for finding in pin_findings],
            ["RELEASE_POLICY_PIN_MALFORMED"],
        )

    def test_inline_comment_occurrence_is_not_consumed_by_valid_uses(self) -> None:
        source = (
            "jobs:\n  release:\n    uses: ryanduguid/release-policy/"
            ".github/workflows/release-python.yml@"
            "3b8a377207cab2c7c808fcc96b66578f4695beea"
            "  # ryanduguid/release-policy/.github/workflows/"
            "release-python.yml@main\n"
        )

        pin_findings = [
            finding
            for finding in evaluate(
                small_policy(), collection(snapshot(workflow_source=source)), self.now
            )
            if finding.code.startswith("RELEASE_POLICY_PIN_")
        ]

        self.assertEqual(
            [finding.code for finding in pin_findings],
            ["RELEASE_POLICY_PIN_MALFORMED"],
        )

    def test_independent_baseline_exemptions_suppress_only_their_checks(self) -> None:
        repository = replace(
            snapshot(),
            paths=frozenset(),
            workflow_sources={},
        )
        policy = replace(
            small_policy(),
            workflow_exemptions={"expected": "reusable workflow repository"},
            dependabot_exemptions={"expected": "generated repository"},
        )
        codes = {finding.code for finding in evaluate(policy, collection(repository), self.now)}
        self.assertNotIn("WORKFLOW_BASELINE_MISSING", codes)
        self.assertNotIn("DEPENDABOT_BASELINE_MISSING", codes)

    def test_success_is_healthy_and_cancelled_is_notice(self) -> None:
        success = snapshot(
            runs=(WorkflowRun(42, ".github/workflows/release.yml", "success"),)
        )
        success_codes = {
            finding.code for finding in evaluate(small_policy(), collection(success), self.now)
        }
        self.assertNotIn("WORKFLOW_RUN_FAILED", success_codes)
        self.assertNotIn("WORKFLOW_RUN_NOTICE", success_codes)
        cancelled = snapshot(
            runs=(WorkflowRun(43, ".github/workflows/release.yml", "cancelled"),)
        )
        notices = [
            finding
            for finding in evaluate(small_policy(), collection(cancelled), self.now)
            if finding.code == "WORKFLOW_RUN_NOTICE"
        ]
        self.assertEqual([finding.severity for finding in notices], [Severity.NOTICE])

    def test_approved_release_policy_pin_has_no_pin_finding(self) -> None:
        source = "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml@3b8a377207cab2c7c808fcc96b66578f4695beea\n"
        repository = snapshot(
            workflow_source=source,
            runs=(WorkflowRun(42, ".github/workflows/release.yml", "success"),),
        )
        codes = {finding.code for finding in evaluate(small_policy(), collection(repository), self.now)}
        self.assertNotIn("RELEASE_POLICY_PIN_MALFORMED", codes)
        self.assertNotIn("RELEASE_POLICY_PIN_UNAPPROVED", codes)

    def test_findings_sort_unstable_input_by_severity_repository_code_and_url(self) -> None:
        result = CollectionResult(
            discovered_repositories=("zeta", "alpha"),
            repositories=(),
            problems=(),
            request_count=1,
            rate_limit={"limit": "5000", "remaining": "4999", "reset": "1"},
        )
        findings = evaluate(small_policy(), result, self.now)
        unexpected = [
            finding.repository
            for finding in findings
            if finding.code == "UNEXPECTED_REPOSITORY"
        ]
        self.assertEqual(unexpected, ["alpha", "zeta"])

    def test_source_url_quotes_a_branch_slash(self) -> None:
        source = "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml@47480b782926179b621ec1c6643ef88c80fc8fd4\n"
        repository = replace(
            snapshot(workflow_source=source),
            default_branch="feature/a",
        )
        findings = evaluate(small_policy(), collection(repository), self.now)
        pin_finding = next(
            finding
            for finding in findings
            if finding.code == "RELEASE_POLICY_PIN_UNAPPROVED"
        )
        self.assertEqual(
            pin_finding.url,
            "https://github.com/ryanduguid/expected/blob/feature%2Fa/.github/workflows/release.yml",
        )


class RenderingTests(unittest.TestCase):
    def test_complete_healthy_estate_is_all_clear(self) -> None:
        now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
        source = "jobs:\n  release:\n    uses: ryanduguid/release-policy/.github/workflows/release-python.yml@3b8a377207cab2c7c808fcc96b66578f4695beea\n"
        repository = snapshot(
            workflow_source=source,
            runs=(WorkflowRun(42, ".github/workflows/release.yml", "success"),),
        )
        result = collection(repository)
        report = build_report(
            small_policy(),
            result,
            evaluate(small_policy(), result, now),
            now,
            now,
        )
        self.assertEqual(report.status, AuditStatus.ALL_CLEAR)

    def test_incomplete_status_precedes_valid_action_findings(self) -> None:
        now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
        repository = replace(snapshot(), paths=frozenset(), workflow_sources={})
        result = collection(
            repository,
            problems=(CollectionProblem("GITHUB_RATE_LIMITED", None, "rate limit unavailable"),),
        )
        findings = evaluate(small_policy(), result, now)
        self.assertIn(Severity.ACTION, {finding.severity for finding in findings})
        report = build_report(small_policy(), result, findings, now, now)
        self.assertEqual(report.status, AuditStatus.INCOMPLETE)
        self.assertIn("INCOMPLETE", render_text(report).splitlines()[0])

    def test_sender_accepts_the_text_heading_the_audit_writes(self) -> None:
        now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
        clean = collection(snapshot())
        repository = replace(snapshot(), paths=frozenset(), workflow_sources={})
        incomplete = collection(
            repository,
            problems=(CollectionProblem("GITHUB_RATE_LIMITED", None, "rate limit unavailable"),),
        )
        for result in (clean, incomplete):
            report = build_report(
                small_policy(), result, evaluate(small_policy(), result, now), now, now
            )
            with self.subTest(status=report.status), tempfile.TemporaryDirectory() as directory:
                json_path = Path(directory) / "audit.json"
                text_path = Path(directory) / "audit.txt"
                write_outputs(report, json_path, text_path)
                _, text = load_reports(json_path, text_path)
                self.assertEqual(text, render_text(report))

    def test_build_report_maps_every_field_and_renders_collection_errors(self) -> None:
        started = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
        finished = started + timedelta(seconds=3)
        result = collection(
            snapshot(),
            problems=(CollectionProblem("TREE_TRUNCATED", "expected", "tree was truncated"),),
        )
        findings = evaluate(small_policy(), result, finished)
        report = build_report(small_policy(), result, findings, started, finished)
        self.assertEqual(report.schema_version, 1)
        self.assertEqual(report.owner, "ryanduguid")
        self.assertEqual(report.started_at, started)
        self.assertEqual(report.finished_at, finished)
        self.assertEqual(report.repository_count, 1)
        self.assertEqual(report.request_count, 4)
        self.assertEqual(report.rate_limit["remaining"], "4900")
        self.assertEqual(report.collection_errors, result.problems)
        self.assertIn(
            "[ERROR] expected TREE_TRUNCATED: tree was truncated",
            render_text(report),
        )

    def test_json_and_text_are_deterministic_and_exclude_sensitive_sentinel(self) -> None:
        now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
        result = collection(snapshot())
        report = build_report(small_policy(), result, evaluate(small_policy(), result, now), now, now)
        first_json = render_json(report)
        second_json = render_json(report)
        self.assertEqual(first_json, second_json)
        self.assertTrue(first_json.endswith("\n"))
        self.assertNotIn("SENSITIVE-BODY-SENTINEL", first_json + render_text(report))


class OutputPathTests(unittest.TestCase):
    def test_writer_rechecks_aliases_created_by_the_first_output(self) -> None:
        now = datetime(2026, 8, 26, 12, tzinfo=UTC)
        report = build_report(small_policy(), collection(snapshot()), (), now, now)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, alias = root / "long-report.json", root / "short-alias.json"
            resolve = Path.resolve

            def resolve_created_alias(path, strict=False):
                # Model a filesystem alias that exists only after its target is created.
                if path == alias and output.exists():
                    return resolve(output, strict=strict)
                return resolve(path, strict=strict)

            with patch.object(Path, "resolve", resolve_created_alias):
                with self.assertRaises(ValueError):
                    write_outputs(report, output, alias)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["status"], "ALL_CLEAR")
            self.assertFalse(alias.exists())

    @unittest.skipUnless(os.name == "nt", "Windows path aliases")
    def test_cli_rejects_ambiguous_windows_paths_before_writing(self) -> None:
        for spelling in ("extended", "device", "trailing dot", "trailing space"):
            for argument in ("policy", "json-output", "text-output"):
                with (
                    self.subTest(spelling=spelling, argument=argument),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    policy = root / "policy.json"
                    policy.write_text("fabricated policy", encoding="utf-8")
                    paths = {
                        "policy": str(policy),
                        "json-output": str(root / "audit.json"),
                        "text-output": str(root / "audit.txt"),
                    }
                    if spelling in ("extended", "device"):
                        prefix = "\\\\?\\" if spelling == "extended" else "\\\\.\\"
                        paths[argument] = prefix + paths[argument]
                    else:
                        paths[argument] += "." if spelling == "trailing dot" else " "
                    arguments = [item for name, path in paths.items() for item in ("--" + name, path)]
                    self.assertEqual(main(arguments, environ={}), 2)
                    self.assertEqual(policy.read_text(encoding="utf-8"), "fabricated policy")
                    self.assertFalse((root / "audit.json").exists())
                    self.assertFalse((root / "audit.txt").exists())

    @unittest.skipUnless(os.name == "nt", "Windows path aliases")
    def test_writer_rejects_windows_aliases_for_new_outputs(self) -> None:
        now = datetime(2026, 8, 26, 12, tzinfo=UTC)
        report = build_report(small_policy(), collection(snapshot()), (), now, now)
        for spelling in ("extended", "trailing dot", "trailing space"):
            with self.subTest(spelling=spelling), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "audit.out"
                alias = (
                    Path("\\\\?\\" + str(output)) if spelling == "extended"
                    else Path(str(output) + ("." if spelling == "trailing dot" else " "))
                )
                with self.assertRaises(ValueError):
                    write_outputs(report, output, alias)
                self.assertFalse(output.exists())

    def test_writer_rejects_separate_symlinks_to_one_target(self) -> None:
        now = datetime(2026, 8, 26, 12, tzinfo=UTC)
        report = build_report(small_policy(), collection(snapshot()), (), now, now)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "existing.out"
            target.write_text("existing report", encoding="utf-8")
            first, second = root / "first.out", root / "second.out"
            try:
                first.symlink_to(target)
                second.symlink_to(target)
            except OSError as error:
                self.skipTest(f"Cannot create local symlinks: {error}")
            with self.assertRaises(ValueError):
                write_outputs(report, first, second)
            self.assertTrue(first.is_symlink() and second.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "existing report")

    def test_writer_rejects_shared_and_relative_output_paths(self) -> None:
        now = datetime(2026, 8, 26, 12, tzinfo=UTC)
        clean = collection(snapshot())
        report = build_report(small_policy(), clean, (), now, now)
        for relative in (False, True):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "audit.out"
                output.write_text("existing report", encoding="utf-8")
                (root / "child").mkdir()
                other = root / "child" / ".." / output.name if relative else output
                with self.assertRaises(ValueError):
                    write_outputs(report, output, other)
                self.assertEqual(output.read_text(encoding="utf-8"), "existing report")

    def test_cli_rejects_output_and_policy_collisions_without_writing(self) -> None:
        for collision in ("outputs", "json-policy", "text-policy"):
            with self.subTest(collision=collision), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                policy, json_path, text_path = root / "policy.json", root / "audit.json", root / "audit.txt"
                policy.write_text("fabricated policy", encoding="utf-8")
                if collision == "outputs":
                    text_path = json_path
                    json_path.write_text("existing report", encoding="utf-8")
                elif collision == "json-policy":
                    json_path = policy
                else:
                    text_path = policy
                with patch("scripts.portfolio_audit.GitHubClient") as client:
                    code = main([
                        "--policy", str(policy), "--json-output", str(json_path),
                        "--text-output", str(text_path),
                    ], environ={})
                client.assert_not_called()
                self.assertEqual(code, 2)
                self.assertEqual(policy.read_text(encoding="utf-8"), "fabricated policy")
                if collision == "outputs":
                    self.assertEqual(json_path.read_text(encoding="utf-8"), "existing report")
                else:
                    other = text_path if collision == "json-policy" else json_path
                    self.assertFalse(other.exists())

    def test_writer_rejects_directory_symlink_aliases(self) -> None:
        now = datetime(2026, 8, 26, 12, tzinfo=UTC)
        clean = collection(snapshot())
        report = build_report(small_policy(), clean, (), now, now)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alias = root / "alias"
            try:
                alias.symlink_to(root, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"Cannot create a local directory symlink: {error}")
            output = root / "audit.out"
            output.write_text("existing report", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_outputs(report, output, alias / output.name)
            self.assertEqual(output.read_text(encoding="utf-8"), "existing report")

    def test_cli_rejects_resolved_policy_aliases(self) -> None:
        for alias_kind in ("policy link", "policy chain", "output link", "parent link"):
            for output_kind in ("json", "text"):
                with (
                    self.subTest(alias=alias_kind, output=output_kind),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    target = root / "policy.json"
                    target.write_text("fabricated policy", encoding="utf-8")
                    policy, output = target, target
                    try:
                        if alias_kind in ("policy link", "policy chain"):
                            policy = root / "policy-link.json"
                            if alias_kind == "policy chain":
                                output = root / "middle-link.json"
                                output.symlink_to(target)
                            policy.symlink_to(output)
                        elif alias_kind == "output link":
                            output = root / "output-link.json"
                            output.symlink_to(target)
                        else:
                            alias = root / "alias"
                            alias.symlink_to(root, target_is_directory=True)
                            output = alias / target.name
                    except OSError as error:
                        self.skipTest(f"Cannot create a local symlink: {error}")
                    other = root / "other-report"
                    json_path, text_path = (output, other) if output_kind == "json" else (other, output)
                    code = main([
                        "--policy", str(policy), "--json-output", str(json_path),
                        "--text-output", str(text_path),
                    ], environ={})
                    self.assertEqual(code, 2)
                    self.assertEqual(target.read_text(encoding="utf-8"), "fabricated policy")
                    self.assertEqual(policy.read_text(encoding="utf-8"), "fabricated policy")
                    self.assertFalse(other.exists())

    def test_separate_hard_links_remain_safe_report_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy, json_path, text_path = root / "policy.json", root / "audit.json", root / "audit.txt"
            policy.write_text("fabricated policy", encoding="utf-8")
            try:
                json_path.hardlink_to(policy)
                text_path.hardlink_to(policy)
            except OSError as error:
                self.skipTest(f"Cannot create local hard links: {error}")
            code = main([
                "--policy", str(policy), "--json-output", str(json_path),
                "--text-output", str(text_path),
            ], environ={})
            self.assertEqual(code, 0)
            self.assertEqual(policy.read_text(encoding="utf-8"), "fabricated policy")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["status"], "INCOMPLETE")
            self.assertIn("INCOMPLETE", text_path.read_text(encoding="utf-8"))

    def test_unresolvable_paths_prevent_both_writes(self) -> None:
        now = datetime(2026, 8, 26, 12, tzinfo=UTC)
        clean = collection(snapshot())
        report = build_report(small_policy(), clean, (), now, now)
        with (
            patch.object(Path, "resolve", side_effect=OSError("fabricated resolution failure")),
            patch("scripts.portfolio_audit._atomic_write") as writer,
        ):
            with self.assertRaises(OSError):
                write_outputs(report, Path("audit.json"), Path("audit.txt"))
            code = main([
                "--policy", "policy.json", "--json-output", "audit.json",
                "--text-output", "audit.txt",
            ], environ={})
            self.assertEqual(code, 2)
        writer.assert_not_called()


class CliTests(unittest.TestCase):
    def test_missing_token_writes_incomplete_outputs_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_path = root / "audit.json"
            text_path = root / "audit.txt"
            with patch(
                "scripts.portfolio_audit.GitHubClient",
                side_effect=AssertionError("network client must not be constructed"),
            ) as client_constructor:
                exit_code = main(
                    [
                        "--policy", "portfolio-audit-policy.json",
                        "--json-output", str(json_path),
                        "--text-output", str(text_path),
                        "--now", "2026-08-26T12:00:00Z",
                    ],
                    environ={},
                )
            client_constructor.assert_not_called()
            self.assertEqual(exit_code, 0)
            value = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(value["status"], "INCOMPLETE")
            self.assertEqual(value["collection_errors"][0]["code"], "GITHUB_APP_TOKEN_MISSING")

    def test_invalid_policy_still_writes_safe_incomplete_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            json_path = root / "audit.json"
            text_path = root / "audit.txt"
            policy_path.write_text("{}", encoding="utf-8")
            exit_code = main(
                [
                    "--policy", str(policy_path),
                    "--json-output", str(json_path),
                    "--text-output", str(text_path),
                    "--now", "2026-08-26T12:00:00Z",
                ],
                environ={"PORTFOLIO_AUDIT_GITHUB_TOKEN": "token"},
            )
            self.assertEqual(exit_code, 0)
            value = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(value["status"], "INCOMPLETE")
            self.assertEqual(value["collection_errors"][0]["code"], "POLICY_INVALID")

    def test_typed_and_unexpected_collector_failures_write_safe_reports(self) -> None:
        cases = (
            (ResponseError("SENSITIVE-RESPONSE-SENTINEL"), "GITHUB_RESPONSE_INVALID"),
            (RuntimeError("SENSITIVE-UNEXPECTED-SENTINEL"), "COLLECTOR_UNEXPECTED_FAILURE"),
        )
        for error, expected_code in cases:
            with self.subTest(expected_code=expected_code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                json_path = root / "audit.json"
                text_path = root / "audit.txt"
                stderr = io.StringIO()
                with (
                    patch("scripts.portfolio_audit.collect_estate", side_effect=error),
                    contextlib.redirect_stderr(stderr),
                ):
                    exit_code = main(
                        [
                            "--policy", "portfolio-audit-policy.json",
                            "--json-output", str(json_path),
                            "--text-output", str(text_path),
                            "--now", "2026-08-26T12:00:00Z",
                        ],
                        environ={"PORTFOLIO_AUDIT_GITHUB_TOKEN": "token"},
                    )
                json_text = json_path.read_text(encoding="utf-8")
                text_text = text_path.read_text(encoding="utf-8")
                combined = json_text + text_text
                self.assertEqual(exit_code, 0)
                self.assertEqual(json.loads(json_text)["status"], "INCOMPLETE")
                self.assertIn(expected_code, combined)
                self.assertNotIn("SENSITIVE-", combined)
                # An unexpected failure names its type and stack for the operator,
                # never its message.
                self.assertNotIn("SENSITIVE-", stderr.getvalue())
                if expected_code == "COLLECTOR_UNEXPECTED_FAILURE":
                    self.assertIn("RuntimeError (message withheld)", stderr.getvalue())
                    self.assertIn("portfolio_audit.py", stderr.getvalue())

    def test_unexpected_evaluation_or_report_build_failure_writes_minimal_report(self) -> None:
        for target in ("evaluate", "build_report"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                json_path = root / "audit.json"
                text_path = root / "audit.txt"
                with (
                    patch(
                        "scripts.portfolio_audit.collect_estate",
                        return_value=collection(snapshot()),
                    ),
                    patch(
                        f"scripts.portfolio_audit.{target}",
                        side_effect=RuntimeError("SENSITIVE-EVALUATION-SENTINEL"),
                    ),
                ):
                    exit_code = main(
                        [
                            "--policy", "portfolio-audit-policy.json",
                            "--json-output", str(json_path),
                            "--text-output", str(text_path),
                            "--now", "2026-08-26T12:00:00Z",
                        ],
                        environ={"PORTFOLIO_AUDIT_GITHUB_TOKEN": "token"},
                    )

                json_text = json_path.read_text(encoding="utf-8")
                text_text = text_path.read_text(encoding="utf-8")
                value = json.loads(json_text)
                self.assertEqual(exit_code, 0)
                self.assertEqual(value["status"], "INCOMPLETE")
                self.assertEqual(value["repository_count"], 0)
                self.assertEqual(value["request_count"], 0)
                self.assertEqual(value["findings"], [])
                self.assertEqual(
                    value["collection_errors"],
                    [
                        {
                            "code": "COLLECTOR_UNEXPECTED_FAILURE",
                            "repository": None,
                            "summary": "portfolio audit collection failed unexpectedly",
                        }
                    ],
                )
                self.assertIn(
                    "COLLECTOR_UNEXPECTED_FAILURE: portfolio audit collection failed unexpectedly",
                    text_text,
                )
                self.assertNotIn("SENSITIVE-EVALUATION-SENTINEL", json_text + text_text)

    def test_atomic_output_failure_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first", Path(directory) / "second"
            first.mkdir()
            second.mkdir()
            exit_code = main(
                [
                    "--policy", "portfolio-audit-policy.json",
                    "--json-output", str(first),
                    "--text-output", str(second),
                    "--now", "2026-08-26T12:00:00Z",
                ],
                environ={},
            )
            self.assertEqual(exit_code, 2)

    def test_output_failure_still_attempts_the_other_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            text_path = Path(directory) / "audit.txt"
            exit_code = main(
                [
                    "--policy", "portfolio-audit-policy.json",
                    "--json-output", ".",
                    "--text-output", str(text_path),
                    "--now", "2026-08-26T12:00:00Z",
                ],
                environ={},
            )
            self.assertEqual(exit_code, 2)
            self.assertIn("INCOMPLETE", text_path.read_text(encoding="utf-8"))
