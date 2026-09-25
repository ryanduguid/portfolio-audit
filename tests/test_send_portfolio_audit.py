import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from email.message import EmailMessage
from pathlib import Path

from scripts.send_portfolio_audit import (
    MAX_REPORT_BYTES,
    MailConfigError,
    ReportError,
    build_message,
    load_mail_config,
    load_reports,
    main,
    send_report,
)


def report_value(status: str = "ACTION_REQUIRED", action_count: int = 2) -> dict[str, object]:
    findings = [
        {
            "severity": "ACTION",
            "repository": f"repository-{index}",
            "code": "DEPENDABOT_BASELINE_MISSING",
            "summary": "missing .github/dependabot.yml",
            "url": f"https://github.com/ryanduguid/repository-{index}",
        }
        for index in range(action_count)
    ]
    return {
        "schema_version": 1,
        "owner": "ryanduguid",
        "status": status,
        "findings": findings,
        "collection_errors": [],
    }


class MailConfigTests(unittest.TestCase):
    def test_accepts_exactly_one_bare_address_and_token(self) -> None:
        config = load_mail_config(
            {
                "PORTFOLIO_AUDIT_EMAIL": "audit@example.invalid",
                "PROTON_SMTP_TOKEN": "smtp-secret",
            }
        )
        self.assertEqual(config.email, "audit@example.invalid")
        self.assertEqual(config.host, "smtp.protonmail.ch")
        self.assertEqual(config.port, 587)

    def test_rejects_missing_email_or_token(self) -> None:
        with self.assertRaisesRegex(MailConfigError, "mail configuration"):
            load_mail_config({})

    def test_rejects_header_injection_display_name_or_multiple_addresses(self) -> None:
        invalid_values = (
            "audit@example.invalid\r\nBcc: attacker@example.invalid",
            "Operator <audit@example.invalid>",
            "first@example.invalid,second@example.invalid",
        )
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(MailConfigError):
                    load_mail_config(
                        {
                            "PORTFOLIO_AUDIT_EMAIL": value,
                            "PROTON_SMTP_TOKEN": "smtp-secret",
                        }
                    )

    def test_parse_failure_does_not_retain_rejected_address(self) -> None:
        sentinel = "SENSITIVE-ADDRESS-SENTINEL"
        with self.assertRaises(MailConfigError) as raised:
            load_mail_config(
                {
                    "PORTFOLIO_AUDIT_EMAIL": f"{sentinel}@@example.invalid",
                    "PROTON_SMTP_TOKEN": "smtp-secret",
                }
            )
        self.assertEqual(str(raised.exception), "invalid mail configuration")
        self.assertNotIn(sentinel, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)


class MessageTests(unittest.TestCase):
    def test_subject_is_fixed_from_status_and_action_count(self) -> None:
        config = load_mail_config(
            {
                "PORTFOLIO_AUDIT_EMAIL": "audit@example.invalid",
                "PROTON_SMTP_TOKEN": "smtp-secret",
            }
        )
        message = build_message(
            config,
            report_value(),
            "GitHub portfolio audit: ACTION_REQUIRED (2 action findings)\n",
        )
        self.assertEqual(message["Subject"], "[GitHub portfolio audit] ACTION_REQUIRED (2)")
        self.assertEqual(message["From"], "audit@example.invalid")
        self.assertEqual(message["To"], "audit@example.invalid")
        self.assertIn("ACTION_REQUIRED", message.get_content())

    def test_rejects_unknown_status_and_mismatched_action_count(self) -> None:
        config = load_mail_config(
            {
                "PORTFOLIO_AUDIT_EMAIL": "audit@example.invalid",
                "PROTON_SMTP_TOKEN": "smtp-secret",
            }
        )
        with self.assertRaises(ReportError):
            build_message(config, report_value("UNKNOWN", 0), "report\n")
        mismatched = report_value("ACTION_REQUIRED", 2)
        mismatched["findings"] = []
        with self.assertRaises(ReportError):
            build_message(config, mismatched, "report\n")

    def test_rejects_deceptive_text_status_first_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_path = root / "audit.json"
            text_path = root / "audit.txt"
            json_path.write_text(
                json.dumps(report_value("ALL_CLEAR", 0)),
                encoding="utf-8",
            )
            text_path.write_text(
                "GitHub portfolio audit: NOT_ALL_CLEAR\n",
                encoding="utf-8",
            )
            with self.assertRaises(ReportError):
                load_reports(json_path, text_path)

    def test_rejects_text_heading_whose_counts_differ_from_the_json(self) -> None:
        for status, heading in (
            ("ALL_CLEAR", "GitHub portfolio audit: ALL_CLEAR (9 action findings)"),
            ("ALL_CLEAR", "GitHub portfolio audit: ALL_CLEAR"),
            ("ACTION_REQUIRED", "GitHub portfolio audit: ACTION_REQUIRED (1 action findings)"),
        ):
            with self.subTest(heading=heading), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                json_path = root / "audit.json"
                text_path = root / "audit.txt"
                json_path.write_text(
                    json.dumps(report_value(status, 0 if status == "ALL_CLEAR" else 2)),
                    encoding="utf-8",
                )
                text_path.write_text(heading + "\n", encoding="utf-8")
                with self.assertRaises(ReportError):
                    load_reports(json_path, text_path)

    def test_rejects_a_report_over_the_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oversized = root / "audit.json"
            text_path = root / "audit.txt"
            oversized.write_bytes(b"x" * (MAX_REPORT_BYTES + 1))
            text_path.write_text("GitHub portfolio audit: ALL_CLEAR\n", encoding="utf-8")
            with self.assertRaisesRegex(ReportError, "size limit"):
                load_reports(oversized, text_path)


class FakeSmtp:
    instances: list["FakeSmtp"] = []

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        self.events: list[object] = [("connect", host, port, timeout)]
        self.__class__.instances.append(self)

    def __enter__(self) -> "FakeSmtp":
        return self

    def __exit__(self, *args: object) -> None:
        self.events.append("quit")

    def ehlo(self) -> None:
        self.events.append("ehlo")

    def starttls(self, *, context: object) -> None:
        self.events.append(("starttls", context is not None))

    def login(self, username: str, password: str) -> None:
        self.events.append(("login", username, password))

    def send_message(self, message: EmailMessage) -> None:
        self.events.append(("send", message["Subject"]))


class SmtpDeliveryTests(unittest.TestCase):
    def setUp(self) -> None:
        FakeSmtp.instances.clear()
        self.environ = {
            "PORTFOLIO_AUDIT_EMAIL": "audit@example.invalid",
            "PROTON_SMTP_TOKEN": "SENSITIVE-SMTP-TOKEN",
        }

    def test_starttls_precedes_login_and_send(self) -> None:
        config = load_mail_config(self.environ)
        message = build_message(config, report_value(), "plain-text report\n")
        send_report(config, message, smtp_factory=FakeSmtp)
        events = FakeSmtp.instances[0].events
        self.assertEqual(events[0], ("connect", "smtp.protonmail.ch", 587, 30))
        self.assertEqual(events[1], "ehlo")
        self.assertEqual(events[2], ("starttls", True))
        self.assertEqual(events[3], "ehlo")
        self.assertEqual(events[4], ("login", "audit@example.invalid", "SENSITIVE-SMTP-TOKEN"))
        self.assertEqual(events[5], ("send", message["Subject"]))
        self.assertEqual(events[6], "quit")

    def test_main_reports_only_exception_class_on_delivery_failure(self) -> None:
        class RejectingSmtp(FakeSmtp):
            def login(self, username: str, password: str) -> None:
                raise RuntimeError(f"rejected {password}")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            json_path = root / "audit.json"
            text_path = root / "audit.txt"
            json_path.write_text(json.dumps(report_value()), encoding="utf-8")
            text_path.write_text(
                "GitHub portfolio audit: ACTION_REQUIRED (2 action findings)\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                exit_code = main(
                    ["--json-report", str(json_path), "--text-report", str(text_path)],
                    environ=self.environ,
                    smtp_factory=RejectingSmtp,
                )
        self.assertEqual(exit_code, 1)
        self.assertIn("RuntimeError", stderr.getvalue())
        self.assertNotIn("SENSITIVE-SMTP-TOKEN", stderr.getvalue())

    def test_missing_report_fails_before_smtp_connection(self) -> None:
        exit_code = main(
            ["--json-report", "missing.json", "--text-report", "missing.txt"],
            environ=self.environ,
            smtp_factory=FakeSmtp,
        )
        self.assertEqual(exit_code, 1)
        self.assertEqual(FakeSmtp.instances, [])

    def test_cli_parse_failure_uses_class_only_boundary(self) -> None:
        sentinel = "--SENSITIVE-UNKNOWN-ARGUMENT"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            try:
                exit_code = main(
                    [
                        "--json-report",
                        "missing.json",
                        "--text-report",
                        "missing.txt",
                        sentinel,
                    ],
                    environ=self.environ,
                    smtp_factory=FakeSmtp,
                )
            except SystemExit as error:
                self.fail(f"main raised SystemExit({error.code})")
        self.assertEqual(exit_code, 1)
        self.assertEqual(
            stderr.getvalue(),
            "Portfolio audit email failed (ValueError).\n",
        )
        self.assertNotIn(sentinel, stderr.getvalue())
        self.assertEqual(FakeSmtp.instances, [])
