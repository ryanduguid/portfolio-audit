from __future__ import annotations

import argparse
import json
import os
import smtplib
import ssl
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from email.headerregistry import Address
from email.message import EmailMessage
from pathlib import Path
from typing import Any, NoReturn

SMTP_HOST = "smtp.protonmail.ch"
SMTP_PORT = 587
SMTP_TIMEOUT_SECONDS = 30
MAX_REPORT_BYTES = 1024 * 1024
ALLOWED_STATUSES = frozenset({"ALL_CLEAR", "ACTION_REQUIRED", "INCOMPLETE"})


@dataclass(frozen=True)
class MailConfig:
    email: str
    smtp_token: str
    host: str = SMTP_HOST
    port: int = SMTP_PORT


class MailConfigError(ValueError):
    pass


class ReportError(ValueError):
    pass


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("invalid command-line arguments") from None


def load_mail_config(environ: Mapping[str, str]) -> MailConfig:
    email = environ.get("PORTFOLIO_AUDIT_EMAIL")
    smtp_token = environ.get("PROTON_SMTP_TOKEN")
    if not isinstance(email, str) or not email:
        raise MailConfigError("invalid mail configuration")
    if not isinstance(smtp_token, str) or not smtp_token:
        raise MailConfigError("invalid mail configuration")
    if email.strip() != email or any(character in email for character in "\r\n,<>"):
        raise MailConfigError("invalid mail configuration")
    try:
        address = Address(addr_spec=email)
    except Exception:
        address = None
    if address is None:
        raise MailConfigError("invalid mail configuration") from None
    if address.addr_spec != email or str(address) != email:
        raise MailConfigError("invalid mail configuration")
    return MailConfig(email=email, smtp_token=smtp_token)


def _read_report(path: str | Path) -> str:
    with Path(path).open("rb") as report:
        data = report.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ReportError("report exceeds size limit")
    return data.decode("utf-8")


def _validate_report(report: object) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise ReportError("invalid report")
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise ReportError("invalid report")
    if report.get("owner") != "ryanduguid":
        raise ReportError("invalid report")
    status = report.get("status")
    if not isinstance(status, str) or status not in ALLOWED_STATUSES:
        raise ReportError("invalid report")
    if not isinstance(report.get("findings"), list):
        raise ReportError("invalid report")
    if not isinstance(report.get("collection_errors"), list):
        raise ReportError("invalid report")
    return report


def load_reports(
    json_path: str | Path,
    text_path: str | Path,
) -> tuple[dict[str, Any], str]:
    report = _validate_report(json.loads(_read_report(json_path)))
    report_text = _read_report(text_path)
    first_line = report_text.splitlines()[0] if report_text else ""
    if first_line != _expected_heading(report):
        raise ReportError("invalid report")
    return report, report_text


def _action_count(report: dict[str, Any]) -> int:
    return sum(
        isinstance(finding, Mapping) and finding.get("severity") == "ACTION"
        for finding in report["findings"]
    )


def _expected_heading(report: dict[str, Any]) -> str:
    # The text report's first line as portfolio_audit.render_text writes it, so
    # the delivered body cannot state different counts from the subject.
    status = report["status"]
    counts = f"{_action_count(report)} action findings"
    if status == "INCOMPLETE":
        counts += f", {len(report['collection_errors'])} collection errors"
    return f"GitHub portfolio audit: {status} ({counts})"


def build_message(
    config: MailConfig,
    report: object,
    report_text: str,
) -> EmailMessage:
    validated_report = _validate_report(report)
    status = validated_report["status"]
    action_count = _action_count(validated_report)
    if status == "ACTION_REQUIRED" and action_count == 0:
        raise ReportError("invalid report")
    if status == "ALL_CLEAR" and action_count != 0:
        raise ReportError("invalid report")

    message = EmailMessage()
    message["From"] = Address(addr_spec=config.email)
    message["To"] = Address(addr_spec=config.email)
    message["Subject"] = f"[GitHub portfolio audit] {status} ({action_count})"
    message.set_content(report_text, subtype="plain", charset="utf-8")
    return message


def send_report(
    config: MailConfig,
    message: EmailMessage,
    smtp_factory: Callable[..., Any] = smtplib.SMTP,
) -> None:
    context = ssl.create_default_context()
    with smtp_factory(
        config.host,
        config.port,
        timeout=SMTP_TIMEOUT_SECONDS,
    ) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(config.email, config.smtp_token)
        smtp.send_message(message)


def main(
    argv: Sequence[str] | None = None,
    environ: Mapping[str, str] | None = None,
    smtp_factory: Callable[..., Any] = smtplib.SMTP,
) -> int:
    parser = _SafeArgumentParser(allow_abbrev=False)
    parser.add_argument("--json-report", required=True)
    parser.add_argument("--text-report", required=True)

    try:
        arguments = parser.parse_args(argv)
        config = load_mail_config(os.environ if environ is None else environ)
        report, report_text = load_reports(
            arguments.json_report,
            arguments.text_report,
        )
        message = build_message(config, report, report_text)
        send_report(config, message, smtp_factory=smtp_factory)
    except Exception as error:
        print(
            f"Portfolio audit email failed ({type(error).__name__}).",
            file=sys.stderr,
        )
        return 1

    print("Portfolio audit email sent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
