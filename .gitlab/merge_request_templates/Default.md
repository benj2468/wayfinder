<!--
TITLE — must follow Conventional Commits: `type(scope): summary`.
The `lint:mr-title` CI job runs commitlint against the MR title and fails the
pipeline otherwise. Keep the summary lowercase and imperative, <=100 chars.
  types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
  example: feat(metrics): add throughput and node metrics to the management API

Fill in the sections below; delete any that genuinely don't apply (don't leave
empty headings). Prose over checkboxes — explain the *why*, not just the *what*.
-->

## Summary

_What this change does and why, in a few sentences. What could an operator or an
application on top of the mesh now observe or do that they couldn't before?_

## What's included

_Bullet the user- and API-visible changes (new requests/responses, TUI views,
config, wire formats). Note anything that changes existing behaviour._

## Key design decisions

_The non-obvious choices and trade-offs a reviewer should weigh — where state
lives (`no_std` core vs host driver), why a rate vs a counter, compatibility,
etc. Call out anything you're unsure about._

## Testing

_How this was verified: tests added (unit / integration / smoke), suites run,
and any manual checks. State failures or gaps honestly — don't claim green if it
isn't._

## Deferred / follow-ups

_Anything intentionally left out, with the reason, so reviewers don't flag it as
missing and so it isn't forgotten._
