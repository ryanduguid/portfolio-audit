import re
import unittest
from pathlib import Path

import yaml
from yaml.resolver import BaseResolver

WORKFLOW_PATH = Path(".github/workflows/portfolio-audit.yml")
DEPENDABOT_PATH = Path(".github/dependabot.yml")

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# Each pin carries a trailing "# vX.Y.Z" tag comment, which the version group
# must not absorb.
ACTION_USE_RE = re.compile(
    r"^\s*(?:-\s*)?uses:\s*([^@\s]+)@([^\s#]+)\s*(?:#\s*(\S+))?\s*$",
    re.MULTILINE,
)
EXPECTED_ACTION_TAGS = {
    "actions/checkout": "v7.0.1",
    "actions/setup-python": "v7.0.0",
    "actions/create-github-app-token": "v3.2.0",
    "actions/upload-artifact": "v7.0.1",
    "actions/download-artifact": "v8.0.1",
}
EMAIL_LITERAL_RE = re.compile(
    r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE
)
CONTEXT_EXPRESSION_RE = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)
SECRET_OR_VARIABLE_CONTEXT_RE = re.compile(r"\b(?:secrets|vars)\b", re.IGNORECASE)

EXPECTED_ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/create-github-app-token": "bcd2ba49218906704ab6c1aa796996da409d3eb1",
    "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
}
EXPECTED_ACTION_COUNTS = {
    "actions/checkout": 2,
    "actions/setup-python": 2,
    "actions/create-github-app-token": 1,
    "actions/upload-artifact": 1,
    "actions/download-artifact": 1,
}
EXPECTED_SECRET_EXPRESSIONS = [
    "${{ vars.PORTFOLIO_AUDIT_APP_CLIENT_ID }}",
    "${{ secrets.PORTFOLIO_AUDIT_APP_PRIVATE_KEY }}",
    "${{ secrets.PORTFOLIO_AUDIT_EMAIL }}",
    "${{ secrets.PROTON_SMTP_TOKEN }}",
    "${{ (github.event_name == 'schedule' && vars.PORTFOLIO_AUDIT_ENABLED == 'true') || (github.event_name == 'workflow_dispatch' && inputs.send_email) }}",
]


class UniqueKeyLoader(yaml.BaseLoader):
    pass


def _construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_unique_mapping(value: str) -> dict[str, object]:
    parsed = yaml.load(value, Loader=UniqueKeyLoader)
    if not isinstance(parsed, dict):
        raise ValueError("workflow root was not a mapping")
    return parsed


def require_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AssertionError(f"{label} was not a mapping")
    return value


def require_list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise AssertionError(f"{label} was not a list")
    return value


def require_steps(job: dict[str, object]) -> list[dict[str, object]]:
    raw_steps = job.get("steps")
    if not isinstance(raw_steps, list) or not all(
        isinstance(item, dict) for item in raw_steps
    ):
        raise AssertionError("job steps were invalid")
    return raw_steps


def named_step(job: dict[str, object], name: str) -> dict[str, object]:
    matches = [item for item in require_steps(job) if item.get("name") == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one step named {name}")
    return matches[0]


def compact(value: object) -> str:
    return " ".join(str(value).split())


class WorkflowContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.workflow = load_unique_mapping(self.source)
        self.events = require_mapping(self.workflow.get("on"), "events")
        self.jobs = require_mapping(self.workflow.get("jobs"), "jobs")

    def job(self, name: str) -> dict[str, object]:
        return require_mapping(self.jobs.get(name), f"job {name}")

    def test_events_and_root_are_exact(self) -> None:
        self.assertEqual(
            set(self.workflow),
            {"name", "on", "permissions", "concurrency", "jobs"},
        )
        self.assertEqual(self.workflow["name"], "Portfolio audit")
        self.assertEqual(self.workflow["permissions"], {})
        self.assertNotIn("pull_request_target", self.events)
        self.assertEqual(set(self.events), {"schedule", "workflow_dispatch"})
        self.assertEqual(self.events["schedule"], [{"cron": "0 22 * * 0"}])
        dispatch = require_mapping(self.events["workflow_dispatch"], "dispatch")
        self.assertEqual(
            dispatch,
            {
                "inputs": {
                    "send_email": {
                        "description": "Send the generated public-only report by email",
                        "required": "false",
                        "default": "false",
                        "type": "boolean",
                    }
                }
            },
        )
        self.assertEqual(
            self.workflow["concurrency"],
            {
                "group": "portfolio-audit-${{ github.ref }}",
                "cancel-in-progress": "false",
            },
        )

    def test_job_permissions_environments_and_dependencies_are_exact(self) -> None:
        self.assertEqual(
            set(self.jobs), {"invocation_guard", "collect", "deliver", "enforce"}
        )
        expected_permissions = {
            "invocation_guard": {},
            "collect": {"contents": "read"},
            "deliver": {"contents": "read"},
            "enforce": {},
        }
        for name, permissions in expected_permissions.items():
            self.assertEqual(self.job(name).get("permissions"), permissions)

        self.assertEqual(self.job("collect").get("environment"), "portfolio-audit-collect")
        self.assertEqual(self.job("deliver").get("environment"), "portfolio-audit-deliver")
        for name in ("invocation_guard", "enforce"):
            self.assertNotIn("environment", self.job(name))
        self.assertEqual(self.job("collect").get("needs"), "invocation_guard")
        self.assertEqual(self.job("deliver").get("needs"), "collect")
        self.assertEqual(self.job("enforce").get("needs"), ["collect", "deliver"])

    def test_job_conditions_preserve_the_default_branch_and_delivery_gates(self) -> None:
        self.assertEqual(
            compact(self.job("invocation_guard").get("if")),
            "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
        )
        self.assertNotIn("if", self.job("collect"))
        self.assertEqual(
            compact(self.job("deliver").get("if")),
            "needs.collect.result == 'success' && ((github.event_name == 'schedule' && vars.PORTFOLIO_AUDIT_ENABLED == 'true') || (github.event_name == 'workflow_dispatch' && inputs.send_email))",
        )
        self.assertEqual(
            compact(self.job("enforce").get("if")),
            "always() && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')",
        )
        guard = named_step(self.job("invocation_guard"), "Require the default branch")
        self.assertEqual(guard.get("env"), {"AUDIT_REF": "${{ github.ref }}"})
        self.assertIn('"refs/heads/main"', str(guard.get("run")))

    def test_external_actions_are_exact_full_sha_pins(self) -> None:
        action_uses = ACTION_USE_RE.findall(self.source)
        self.assertEqual(len(action_uses), sum(EXPECTED_ACTION_COUNTS.values()))
        counts: dict[str, int] = {}
        for action, pin, tag in action_uses:
            self.assertEqual(pin, EXPECTED_ACTION_PINS[action])
            self.assertRegex(pin, FULL_SHA_RE)
            self.assertEqual(tag, EXPECTED_ACTION_TAGS[action])
            counts[action] = counts.get(action, 0) + 1
        self.assertEqual(counts, EXPECTED_ACTION_COUNTS)

        checkout_steps = [
            item
            for name in ("collect", "deliver")
            for item in require_steps(self.job(name))
            if str(item.get("uses", "")).startswith("actions/checkout@")
        ]
        self.assertEqual(len(checkout_steps), 2)
        for checkout in checkout_steps:
            options = require_mapping(checkout.get("with"), "checkout options")
            self.assertEqual(options.get("persist-credentials"), "false")

        delivery_checkout = named_step(
            self.job("deliver"), "Check out immutable delivery code"
        )
        self.assertEqual(
            delivery_checkout.get("with"),
            {"ref": "${{ github.sha }}", "persist-credentials": "false"},
        )

    def test_github_app_credential_is_confined_to_collection(self) -> None:
        collect = self.job("collect")
        mint = named_step(collect, "Mint read-only GitHub App token")
        self.assertEqual(mint.get("id"), "app-token")
        # A credential that cannot be minted must fail the step rather than
        # hand the collector an empty token, which presented a configuration
        # failure as a successful step and an INCOMPLETE report.
        self.assertNotIn("continue-on-error", mint)
        self.assertEqual(
            mint.get("with"),
            {
                "client-id": "${{ vars.PORTFOLIO_AUDIT_APP_CLIENT_ID }}",
                "private-key": "${{ secrets.PORTFOLIO_AUDIT_APP_PRIVATE_KEY }}",
                "owner": "ryanduguid",
                "permission-actions": "read",
                "permission-contents": "read",
                "permission-pull-requests": "read",
            },
        )
        collector = named_step(collect, "Collect public portfolio evidence")
        self.assertEqual(
            collector.get("env"),
            {"PORTFOLIO_AUDIT_GITHUB_TOKEN": "${{ steps.app-token.outputs.token }}"},
        )
        self.assertEqual(collector.get("shell"), "python")
        self.assertIn("scripts/portfolio_audit.py", str(collector.get("run")))
        self.assertEqual(self.source.count("steps.app-token.outputs.token"), 1)

        collect_source = yaml.dump(collect)
        outside_collect = yaml.dump(
            {name: job for name, job in self.jobs.items() if name != "collect"}
        )
        for marker in (
            "PORTFOLIO_AUDIT_APP_CLIENT_ID",
            "PORTFOLIO_AUDIT_APP_PRIVATE_KEY",
            "steps.app-token.outputs.token",
        ):
            self.assertIn(marker, collect_source)
            self.assertNotIn(marker, outside_collect)

    def test_artifact_is_data_only_and_delivery_code_is_immutable(self) -> None:
        collect = self.job("collect")
        prepare = named_step(collect, "Prepare audit output")
        self.assertEqual(prepare.get("run"), "mkdir -p audit-output")
        upload = named_step(collect, "Upload delivery artefact")
        self.assertEqual(
            upload.get("with"),
            {
                "name": "portfolio-audit-report-${{ github.run_id }}",
                "path": "audit-output/audit.json\naudit-output/audit.txt\n",
                "if-no-files-found": "error",
                "retention-days": "7",
            },
        )
        self.assertNotIn(".py", str(require_mapping(upload.get("with"), "upload")["path"]))

        deliver = self.job("deliver")
        download = named_step(deliver, "Download delivery artefact")
        self.assertEqual(
            download.get("with"),
            {
                "name": "portfolio-audit-report-${{ github.run_id }}",
                "path": "audit-output",
            },
        )
        send = named_step(deliver, "Send public-only digest")
        self.assertEqual(
            send.get("env"),
            {
                "PORTFOLIO_AUDIT_EMAIL": "${{ secrets.PORTFOLIO_AUDIT_EMAIL }}",
                "PROTON_SMTP_TOKEN": "${{ secrets.PROTON_SMTP_TOKEN }}",
            },
        )
        self.assertEqual(
            send.get("run"),
            "python scripts/send_portfolio_audit.py --json-report audit-output/audit.json --text-report audit-output/audit.txt",
        )
        self.assertNotIn("audit-output/send_portfolio_audit.py", self.source)

    def test_secret_and_variable_expressions_are_allowlisted(self) -> None:
        expressions = [
            compact(expression)
            for expression in CONTEXT_EXPRESSION_RE.findall(self.source)
            if SECRET_OR_VARIABLE_CONTEXT_RE.search(expression)
        ]
        self.assertEqual(expressions, EXPECTED_SECRET_EXPRESSIONS)
        self.assertNotIn("toJSON(secrets)", self.source)
        self.assertIsNone(EMAIL_LITERAL_RE.search(self.source))

        deliver_source = yaml.dump(self.job("deliver"))
        outside_deliver = yaml.dump(
            {name: job for name, job in self.jobs.items() if name != "deliver"}
        )
        for marker in ("PORTFOLIO_AUDIT_EMAIL", "PROTON_SMTP_TOKEN"):
            self.assertIn(marker, deliver_source)
            self.assertNotIn(marker, outside_deliver)

    def test_report_summary_and_enforcement_fail_closed(self) -> None:
        report = named_step(self.job("collect"), "Record report status and summary")
        self.assertIn('summary.write(f"    {line}\\n")', str(report.get("run")))
        enforce = named_step(self.job("enforce"), "Enforce report and requested delivery")
        self.assertEqual(
            enforce.get("env"),
            {
                "COLLECT_RESULT": "${{ needs.collect.result }}",
                "REPORT_STATUS": "${{ needs.collect.outputs.report-status }}",
                "REPORT_REASON": "${{ needs.collect.outputs.report-reason }}",
                "DELIVERY_RESULT": "${{ needs.deliver.result }}",
                "DELIVERY_REQUESTED": "${{ (github.event_name == 'schedule' && vars.PORTFOLIO_AUDIT_ENABLED == 'true') || (github.event_name == 'workflow_dispatch' && inputs.send_email) }}",
            },
        )
        script = str(enforce.get("run"))
        self.assertIn('"$COLLECT_RESULT" != "success"', script)
        self.assertIn('"$REPORT_STATUS" != "ALL_CLEAR"', script)
        self.assertIn('"$DELIVERY_RESULT" != "success"', script)

    def test_collection_error_codes_reach_the_enforcement_message(self) -> None:
        self.assertEqual(
            self.job("collect").get("outputs"),
            {
                "report-status": "${{ steps.report.outputs.status }}",
                "report-reason": "${{ steps.report.outputs.reason }}",
            },
        )
        report = str(
            named_step(self.job("collect"), "Record report status and summary").get("run")
        )
        # Only codes matching this shape may reach GITHUB_OUTPUT, so a summary
        # carrying a newline cannot append an output line of its own.
        self.assertIn('re.fullmatch(r"[A-Z0-9_]{1,64}", code)', report)
        self.assertIn('reason = ",".join(sorted(codes))', report)
        self.assertIn('output.write(f"reason={reason}\\n")', report)

        script = str(
            named_step(self.job("enforce"), "Enforce report and requested delivery").get("run")
        )
        self.assertIn(
            'echo "Portfolio audit status: $REPORT_STATUS ($REPORT_REASON)" >&2', script
        )
        # An ACTION_REQUIRED run carries findings rather than collection errors, so
        # it keeps the bare message and stays distinct from missing evidence.
        self.assertIn('echo "Portfolio audit status: $REPORT_STATUS" >&2', script)

    def test_duplicate_yaml_keys_are_rejected(self) -> None:
        changed = self.source.replace(
            "permissions:\n      contents: read\n    outputs:",
            "permissions:\n      contents: read\n      contents: write\n    outputs:",
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate YAML key"):
            load_unique_mapping(changed)


class TestsOnlyWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = Path(".github/workflows/portfolio-tests.yml").read_text(encoding="utf-8")
        self.workflow = load_unique_mapping(self.source)
        self.job = require_mapping(
            require_mapping(self.workflow["jobs"], "jobs")["tests"], "tests job"
        )

    def test_quoted_cancellation_boolean_is_rejected(self) -> None:
        self.source = self.source.replace(
            "cancel-in-progress: true", 'cancel-in-progress: "true"', 1
        )
        self.workflow = load_unique_mapping(self.source)
        with self.assertRaises(AssertionError):
            self.test_only_pr_and_main_push_events_can_start_the_test_job()

    def test_only_pr_and_main_push_events_can_start_the_test_job(self) -> None:
        self.assertEqual(set(self.workflow), {"name", "on", "permissions", "concurrency", "jobs"})
        self.assertEqual(self.workflow["on"], {"pull_request": "", "push": {"branches": ["main"]}})
        self.assertEqual(
            self.workflow["concurrency"],
            {"group": "${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": "true"},
        )
        # BaseLoader deliberately preserves scalar strings for the rest of the
        # contract. Check this boolean's type with the safe resolver separately.
        self.assertIs(
            yaml.safe_load(self.source)["concurrency"]["cancel-in-progress"], True
        )
        self.assertEqual(set(require_mapping(self.workflow["jobs"], "jobs")), {"tests"})
        self.assertEqual(self.workflow["permissions"], {})
        self.assertEqual(self.job["permissions"], {"contents": "read"})
        self.assertEqual(set(self.job), {"name", "runs-on", "timeout-minutes", "permissions", "steps"})
        self.assertEqual(self.job["runs-on"], "ubuntu-latest")
        self.assertEqual(self.job["timeout-minutes"], "10")

    def test_tool_setup_has_exact_pins_and_does_not_persist_credentials(self) -> None:
        steps = require_steps(self.job)
        self.assertEqual(len(steps), 7)
        self.assertEqual(steps[:2], [
            {
                "name": "Check out control repository",
                "uses": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "with": {"persist-credentials": "false"},
            },
            {
                "name": "Set up Python",
                "uses": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
                "with": {"python-version": "3.14"},
            },
        ])

    def test_run_steps_install_pinned_dependencies_lint_type_check_test_and_compile(self) -> None:
        self.assertEqual(require_steps(self.job)[2:], [
            {"name": "Install the pinned development dependencies", "run": "python -m pip install -r requirements-dev.txt"},
            {"name": "Lint", "run": "python -m ruff check ."},
            {"name": "Type check", "run": "python -m mypy scripts tests"},
            {"name": "Run tests", "run": "python -m unittest discover -s tests -p 'test_*.py' -v"},
            {"name": "Compile Python", "run": "python -m compileall -q scripts tests"},
        ])

    def test_requirements_dev_pins_the_declared_versions(self) -> None:
        lines = [
            line.strip()
            for line in Path("requirements-dev.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertEqual(lines, ["PyYAML==6.0.3", "ruff==0.16.6", "mypy==2.3.1"])


class BaselineConfigTests(unittest.TestCase):
    def test_dependabot_tracks_github_actions_weekly(self) -> None:
        value = load_unique_mapping(DEPENDABOT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            value,
            {
                "version": "2",
                "updates": [
                    {
                        "package-ecosystem": "github-actions",
                        "directory": "/",
                        "schedule": {"interval": "weekly"},
                        "cooldown": {"default-days": "7"},
                    }
                ],
            },
        )

    def test_readme_documents_operator_gates_without_values(self) -> None:
        value = Path("README.md").read_text(encoding="utf-8")
        for required in (
            "## Portfolio audit",
            "PORTFOLIO_AUDIT_APP_CLIENT_ID",
            "PORTFOLIO_AUDIT_APP_PRIVATE_KEY",
            "PORTFOLIO_AUDIT_EMAIL",
            "PROTON_SMTP_TOKEN",
            "PORTFOLIO_AUDIT_ENABLED",
            "Actions: read",
            "Contents: read",
            "Pull requests: read",
            "Only select repositories",
            "send_email=false",
            "action-time approval",
        ):
            self.assertIn(required, value)
        self.assertNotRegex(value, EMAIL_LITERAL_RE)


if __name__ == "__main__":
    unittest.main()
