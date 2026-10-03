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

The policy, JSON report and text report must use distinct resolved paths. The
CLI refuses collisions before collection or writing, including aliases through
relative paths or symbolic links. Separate hard-link paths remain usable because
atomic replacement creates separate report files. On Windows, paths with extended
or device namespace prefixes, or components ending in a dot or space, are refused.
An ordinary write failure still allows the other report to be written. The path
check does not protect against
another process changing filesystem links during the run.

The collector keeps default-branch workflow checks separate from release-tag
evidence. It excludes pull-request and merge-group events from default-branch
results. The optional `tagged_release_workflows` policy maps repository names
and workflow filenames to `v` or `component/v` version prefixes. It covers all
18 release callers, whose tag-push runs carry the publish jobs. Other workflows
retain default-branch collection.

Repository names match policy regardless of capitalisation. Workflow filenames
and package paths remain case-sensitive, and reports retain GitHub's repository
spelling. Release-policy pins are approved for the exact workflow filename;
case-distinct filenames keep separate approved commit lists.

For those workflows, the collector also reads the latest 100 completed
workflow runs and considers matching version tags from push, release and manual
dispatch events. It checks the latest eligible tag against the run's repository
and commit, including the peeled commit of annotated tags. Missing or moved tags,
malformed evidence and a branch sharing the tag name produce `INCOMPLETE`.
GitHub drops the ref of a run whose tag was later deleted, such as a failed tag
pushed again after a fix; such a run produces `INCOMPLETE` only while it is the
newest release attempt.
Creation time orders results, so a rerun of an older release cannot hide a newer
failure. A newer default-branch failure still takes precedence. Failed eligible
runs remain action findings; cancelled, skipped and neutral runs remain notices.

Default-branch collection reads the latest 100 completed runs. A workflow
missing from them is looked up by name, so a busy repository cannot hide a
scheduled workflow's failure. A workflow triggered only by `workflow_call` runs
inside its callers' runs, so the audit neither looks it up nor expects a run of
its own. One that can otherwise only be dispatched by hand raises no notice when
it has no run, but its latest failure still counts.

## Release queue

The optional `release_queue` policy lists, for each tagged release workflow, the
package paths its release ships (the wheel's sources and `pyproject.toml`, not
tests or documentation) and the file that declares its version: a
`pyproject.toml` with a static version, a `VERSION` file or a `.py` file setting
`__version__`. Python files must have one direct module-level assignment of a
string literal, optionally annotated. Comments and docstring examples are ignored;
conflicting explicit bindings, computed declarations and malformed Python produce
`INCOMPLETE`. This reads static metadata without executing the file or determining
its eventual runtime value. Accepted syntax depends on the Python version running
the audit. For each component the collector reads that version on the
default branch, finds the component's latest release tag by version order, and
lists commits touching the package paths after the tagged commit's date. Two
action findings follow:

- `RELEASE_VERSION_UNTAGGED`: the declared version has no release tag, so a
  release was prepared and never tagged.
- `RELEASE_CHANGES_UNRELEASED`: the oldest package change after the latest tag
  is more than `max_age_days` old (7), so users of the published release are
  missing it.

A component without any matching tag is a `RELEASE_TAG_MISSING` notice. A
configured path or version file missing from the tree reports
`RELEASE_PATH_MISSING` and `INCOMPLETE`, because a mistyped path would match
nothing and hide the backlog. Policy schema 2 requires each `deferrals` entry
to name an exact unprefixed `version`, a `reason` and an inclusive `review_by`
date. The hold suppresses both action findings only while that version is
untagged. A tagged or different version cannot inherit it. Schema 1 policies
fail with a migration message; add the version and change `schema_version` to 2.
The audit-report schema remains 1.
Committer dates stand in for ancestry, which holds for squash-merged histories.
The queue adds about 2 requests per component plus one per package path. It
compares versions with tags, not with PyPI: the tag run publishes, so a failed
publication already shows as that run's failure, and the collector stays on
GitHub's hosts.

The audit's own `portfolio-audit.yml` run needs a separate check because its
enforcement job fails when the report contains findings. For the latest failed
run, the collector reads the latest attempt's jobs. A failure becomes an
`AUDIT_ENFORCEMENT_FAILED` notice only when all 4 expected jobs are present,
the invocation guard and collection succeeded, delivery succeeded or was
skipped, and the only failed enforcement step was `Enforce report and requested
delivery`. The original run remains failed. The current report evaluates the
estate again, so prior enforcement does not create a recurring action finding.
This notice does not establish that the prior report was complete or clear.
Operational failures and unexpected job or step results remain action findings;
unavailable or malformed job evidence produces `INCOMPLETE`. This adds at most
one API request and does not change enforcement or email delivery.

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

## Scope compared with similar tools

This audit checks how the repositories operate, not how they present:
default-branch and release-tag workflow results, release tags against declared
versions, the release queue, stale Dependabot pull requests and pinned uses of
the release-policy workflows. Two public tools cover neighbouring ground (read
on 29 September 2026):

- [OpenSSF Scorecard](https://github.com/ossf/scorecard) scores security
  practices. It already runs in release-policy's `scorecard.yml` workflow.
- [Samielakkad/github-portfolio-audit](https://github.com/Samielakkad/github-portfolio-audit)
  (MIT) scores whether public repositories are documented, testable, licensed,
  maintained and discoverable, from the description, topics, README, licence,
  workflow triggers, test files and community policies. This audit makes none
  of those presentation checks.

## Licence

MIT licensed. See [LICENSE](LICENSE).
