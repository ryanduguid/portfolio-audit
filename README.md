# Portfolio audit

This public repository owns the account's portfolio audit policy, collection
and delivery code and tests. Public account-level
community files live in [ryanduguid/.github](https://github.com/ryanduguid/.github).

## Local checks

Install the pinned development dependencies before running anything locally:
`python -m pip install -r requirements-dev.txt`. The tests import PyYAML, so
without it `python -m unittest discover -s tests` cannot collect the full suite
and reports import errors. Then run `python -m ruff check .`,
`python -m mypy scripts tests`,
`python -m unittest discover -s tests -p 'test_*.py' -v` and
`python -m compileall -q scripts tests`, the same checks `portfolio-tests.yml`
runs.

## Portfolio audit

The portfolio audit checks active public repositories owned by the account. It
excludes forks and archived repositories, and reports `ALL_CLEAR`,
`ACTION_REQUIRED` or `INCOMPLETE`. Weekly and manual collection runs only from
`main`; pull requests and pushes run `portfolio-tests.yml`, which does not depend
on the operator-controlled audit workflow being enabled.
The delivery artefact contains report data only; the delivery job runs its mail
code from the immutable triggering commit with checkout credentials disabled.

The collector keeps default-branch workflow checks separate from release-tag
evidence. It excludes pull-request and merge-group events from default-branch
results. The optional `tagged_release_workflows` policy maps repository names
and workflow filenames to `v` or `component/v` version prefixes. It currently
covers Australian Accounting's `release-aus-accounting-mcp.yml`, whose tag-push run
now carries the PyPI publish job. Other workflows retain
default-branch collection.

For that workflow, the collector also reads the latest 100 completed
workflow runs and considers matching version tags from push, release and manual
dispatch events. It checks the latest eligible tag against the run's repository
and commit, including the peeled commit of annotated tags. Missing or moved tags,
malformed evidence and a branch sharing the tag name produce `INCOMPLETE`.
Creation time orders results, so a rerun of an older release cannot hide a newer
failure. A newer default-branch failure still takes precedence. Failed eligible
runs remain action findings; cancelled, skipped and neutral runs remain notices.

`ALL_CLEAR` means collection completed with no action findings; it can include
notices. The bounded run windows do not prove that an older workflow never ran,
and successful runs do not replace release-asset or attestation verification.
Every mention of a release-policy workflow path in a consumer workflow must be
a `uses:` reference pinned to a full lowercase commit SHA, or an attestation
signer identity. The latter requires one `--signer-workflow` and one
`--signer-digest` in a standalone `gh attestation verify` command, with shell
comments excluded. The digest must be a full lowercase commit SHA or a shell
variable; this static check does not resolve the variable's runtime value.
Backslash continuations, quoted arguments and `--option=value` are supported.
Other occurrences, including compound shell commands and syntax the parser
cannot read, stay unconsumed and report `RELEASE_POLICY_PIN_MALFORMED`.

Remove a source from `expected_repositories` only after its approved archive
checks pass and a fresh repository-ID lookup confirms it is archived. Remove
that source's `tagged_release_workflows` entry in the same reviewed policy change.
Retain any source that remains active, including Power BI if native validation
excludes it from archival. A passing audit does not replace the observation
period or native acceptance. Keep release-pin allowlists, exemptions, thresholds
and audit/email settings unchanged during this cutover. Add tag-aware workflows
or approved commits through policy review.

Use a personal-account-only [GitHub App authentication from
Actions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/making-authenticated-api-requests-with-a-github-app-in-a-github-actions-workflow)
setup. It must have `Actions: read`, `Contents: read`, `Pull requests: read`
and automatic `Metadata: read`, with no webhook, events, account,
organisation or write permissions. [Install your own GitHub
App](https://docs.github.com/en/apps/using-github-apps/installing-your-own-github-app)
with **Only select repositories**, including only the active public estate.
Use [GitHub's permission
guidance](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
when checking this configuration.

Before adding any App value, create the exact GitHub Environment
`portfolio-audit-collect`. Under its deployment branches and tags, choose
**Selected branches and tags** and add only the `main` branch. GitHub matches
this rule against the workflow run's `GITHUB_REF`. After saving that
restriction, store `PORTFOLIO_AUDIT_APP_CLIENT_ID` as an environment variable
and `PORTFOLIO_AUDIT_APP_PRIVATE_KEY` as an environment secret. Only the
`collect` job references this environment. See [GitHub's environment
documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
for the branch rule and job-scoped value behaviour.

The first manual dry run uses `send_email=false`. An `ACTION_REQUIRED` result
can still be complete even when the enforcement job fails. Review the report
artefact and Actions summary before configuring mail. Correct false positives
through a reviewed policy change, never an ad hoc exemption.

For [Proton SMTP Submission](https://proton.me/support/smtp-submission), create
the exact GitHub Environment `portfolio-audit-deliver`. Before adding either
mail value, choose **Selected branches and tags** and add only the `main`
branch. Then store both `PORTFOLIO_AUDIT_EMAIL` and the dedicated
`PROTON_SMTP_TOKEN` as environment secrets. Only the `deliver` job references
this environment. Never use the mailbox password.

`PORTFOLIO_AUDIT_ENABLED` is the one repository variable in this setup. Keep
it absent or other than `true` during setup, dry runs and the separately
approved test message. `send_email=true` sends a real message.
It requires action-time approval. Enable weekly delivery only after receipt and
content of that test message are confirmed.

Fix missing App or mail configuration in GitHub or Proton settings, never by
pasting it into chat or committing it. If a key or token might be exposed,
rotate it, run a dry audit and inspect the report before re-enabling delivery.
Reports contain public metadata only: do not add private repository, client,
taxpayer, payroll or credential data.

## Licence

MIT licensed. See [LICENSE](LICENSE).
