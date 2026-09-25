import unittest
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

from test_portfolio_audit import (
    FakeTransport,
    api_response,
    blob_sha,
    public_repo,
    small_policy,
    workflow_run,
)

from scripts.portfolio_audit import (
    AuditReport,
    AuditStatus,
    GitHubClient,
    HttpResponse,
    Severity,
    build_report,
    collect_estate,
    evaluate,
)

AUDIT_PATH = ".github/workflows/portfolio-audit.yml"


def audit_jobs(delivery: str = "skipped") -> dict[str, Any]:
    return {
        "total_count": 4,
        "jobs": [
            {
                "name": name,
                "run_id": 42,
                "status": "completed",
                "conclusion": conclusion,
                "steps": [
                    {
                        "name": "Enforce report and requested delivery",
                        "status": "completed",
                        "conclusion": "failure",
                    }
                ]
                if name == "enforce"
                else [],
            }
            for name, conclusion in (
                ("invocation_guard", "success"),
                ("collect", "success"),
                ("deliver", delivery),
                ("enforce", "failure"),
            )
        ],
    }


class AuditSelfCheckTests(unittest.TestCase):
    def audit(
        self,
        jobs: object,
        *,
        name: str = "portfolio-audit",
        path: str = AUDIT_PATH,
        conclusion: str = "failure",
        runs: list[dict[str, object]] | None = None,
        jobs_response: HttpResponse | None = None,
    ) -> tuple[AuditReport, FakeTransport]:
        if runs is None:
            runs = [workflow_run(42, path=path, branch="main", conclusion=conclusion)]
        source = b"name: Audit\njobs: {}\n"
        tree = [
            {"path": item, "type": "blob", "sha": blob_sha(source)}
            for item in {path, ".github/dependabot.yml", *(str(run["path"]) for run in runs)}
        ]

        class Transport(FakeTransport):
            def __init__(self) -> None:
                super().__init__([])

            def request(self, url: str, headers: dict[str, str]) -> HttpResponse:
                self.requests.append((url, headers))
                parsed = urlsplit(url)
                base = f"/repos/ryanduguid/{name}"
                if parsed.path == "/users/ryanduguid/repos":
                    return api_response([{**public_repo(), "name": name}])
                if parsed.path == base + "/git/trees/main":
                    return api_response({"truncated": False, "tree": tree})
                if parsed.hostname == "raw.githubusercontent.com":
                    return HttpResponse(200, {}, source)
                if parsed.path == base + "/actions/runs":
                    return api_response({"workflow_runs": runs})
                if parsed.path == base + "/actions/runs/42/jobs":
                    if parse_qs(parsed.query) != {"filter": ["latest"], "per_page": ["100"]}:
                        raise AssertionError("jobs query must select the latest attempt")
                    return jobs_response if jobs_response is not None else api_response(jobs)
                if parsed.path == base + "/pulls":
                    return api_response([])
                raise AssertionError(f"unexpected request: {url}")

        transport = Transport()
        policy = replace(small_policy(), expected_repositories=(name,))
        result = collect_estate(policy, GitHubClient("TOKEN-SENTINEL", transport=transport))
        now = datetime(2026, 9, 25, tzinfo=UTC)
        return build_report(policy, result, evaluate(policy, result, now), now, now), transport

    def test_enforcement_only_failure_is_a_notice(self) -> None:
        for delivery in ("skipped", "success"):
            with self.subTest(delivery=delivery):
                report, _ = self.audit(audit_jobs(delivery))
                self.assertEqual(report.status, AuditStatus.ALL_CLEAR)
                self.assertEqual(report.collection_errors, ())
                (finding,) = report.findings
                self.assertEqual(finding.code, "AUDIT_ENFORCEMENT_FAILED")
                self.assertEqual(finding.severity, Severity.NOTICE)
                self.assertEqual(
                    finding.url, "https://github.com/ryanduguid/portfolio-audit/actions/runs/42"
                )

    def test_operational_failures_remain_actions(self) -> None:
        for name in ("invocation_guard", "collect", "deliver"):
            for conclusion in ("failure", "cancelled", "timed_out", "skipped"):
                if name == "deliver" and conclusion == "skipped":
                    continue
                with self.subTest(name=name, conclusion=conclusion):
                    jobs = audit_jobs()
                    next(job for job in jobs["jobs"] if job["name"] == name)["conclusion"] = (
                        conclusion
                    )
                    report, _ = self.audit(jobs)
                    self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
                    self.assertIn("WORKFLOW_RUN_FAILED", {f.code for f in report.findings})

    def test_missing_extra_duplicate_and_incomplete_jobs_remain_actions(self) -> None:
        cases = []
        missing = audit_jobs()
        missing["jobs"].pop()
        cases.append(missing)
        truncated = audit_jobs()
        truncated["total_count"] = 101
        cases.append(truncated)
        extra = audit_jobs()
        extra["jobs"].append({**extra["jobs"][0], "name": "unknown"})
        extra["total_count"] = 5
        cases.append(extra)
        duplicate = audit_jobs()
        duplicate["jobs"][1] = duplicate["jobs"][0]
        cases.append(duplicate)
        for field, value in (
            ("run_id", 43),
            ("status", "in_progress"),
            ("name", "renamed"),
            ("conclusion", []),
        ):
            jobs = audit_jobs()
            jobs["jobs"][0][field] = value
            cases.append(jobs)
        for jobs in cases:
            with self.subTest(jobs=jobs):
                report, _ = self.audit(jobs)
                self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)

    def test_enforcement_runner_or_unknown_step_failures_remain_actions(self) -> None:
        for steps in (
            [],
            [{"name": "Set up job", "status": "completed", "conclusion": "failure"}],
            [
                {
                    "name": "Enforce report and requested delivery",
                    "status": "completed",
                    "conclusion": [],
                }
            ],
            [
                {
                    "name": "Enforce report and requested delivery",
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        ):
            jobs = audit_jobs()
            jobs["jobs"][-1]["steps"] = steps
            report, _ = self.audit(jobs)
            self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)

    def test_unavailable_or_malformed_evidence_is_incomplete(self) -> None:
        malformed: tuple[object, ...] = (None, {}, {"jobs": []}, {"total_count": 4, "jobs": [None]})
        for raw in malformed:
            with self.subTest(raw=raw):
                report, _ = self.audit(raw)
                self.assertEqual(report.status, AuditStatus.INCOMPLETE)
        for status in (403, 404, 500):
            report, _ = self.audit(None, jobs_response=HttpResponse(status, {}, b"{}"))
            self.assertEqual(report.status, AuditStatus.INCOMPLETE)

    def test_other_repositories_workflows_and_conclusions_are_unchanged(self) -> None:
        cases: tuple[dict[str, Any], ...] = (
            {"name": "example"},
            {"path": ".github/workflows/tests.yml"},
            {"conclusion": "success"},
            {"conclusion": "timed_out"},
        )
        for options in cases:
            with self.subTest(options=options):
                report, transport = self.audit(audit_jobs(), **options)
                self.assertFalse(any("/jobs?" in url for url, _ in transport.requests))
                self.assertEqual(
                    report.status,
                    AuditStatus.ALL_CLEAR
                    if options.get("conclusion") == "success"
                    else AuditStatus.ACTION_REQUIRED,
                )

    def test_only_latest_run_is_considered(self) -> None:
        report, transport = self.audit(
            audit_jobs(),
            runs=[
                workflow_run(42, path=AUDIT_PATH, branch="main", conclusion="failure"),
                workflow_run(43, path=AUDIT_PATH, branch="main", created="2026-09-03T13:40:03Z"),
            ],
        )
        self.assertEqual(report.status, AuditStatus.ALL_CLEAR)
        self.assertFalse(any("/jobs?" in url for url, _ in transport.requests))

    def test_current_findings_are_still_actionable(self) -> None:
        report, _ = self.audit(
            audit_jobs(),
            runs=[
                workflow_run(42, path=AUDIT_PATH, branch="main", conclusion="failure"),
                workflow_run(
                    43, path=".github/workflows/another.yml", branch="main", conclusion="failure"
                ),
            ],
        )
        self.assertEqual(report.status, AuditStatus.ACTION_REQUIRED)
        self.assertEqual(
            {f.code for f in report.findings}, {"AUDIT_ENFORCEMENT_FAILED", "WORKFLOW_RUN_FAILED"}
        )
