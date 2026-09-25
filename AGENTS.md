# Repository instructions

Before changing audit policy, collection or delivery, read [README.md](README.md).
Keep collection, evaluation and delivery separate.
Preserve the distinction between `ALL_CLEAR`, `ACTION_REQUIRED` and `INCOMPLETE`;
missing evidence must remain visible.

Policy changes must preserve the documented archive verification and review
requirements. Keep credential handling, environments and delivery controls under
their existing approval process. Use fabricated fixtures and public metadata;
private repository content and client data do not belong in reports.

Before handoff, run the test-only checks in
[portfolio-tests.yml](.github/workflows/portfolio-tests.yml). Those checks require
neither live collection nor email delivery. Report live collection and delivery
as separate gates and obtain explicit authorisation before sending a message.
