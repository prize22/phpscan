# Security policy

phpscan is a local static analyzer that runs on your machine against your
own codebases. It is designed to be part of your security tooling.

## Reporting a vulnerability in phpscan itself

If phpscan has a security issue (e.g. arbitrary file write during scan,
parsing-induced code Execution, etc.), open a minimal report via GitHub
obby (issues) — I will triage within 1-2 days. Note: phpscan does not run
target code, so the classic "malicious input crashes the scanner" issues
are (bounded by parse guardrails) — still report if you trigger one.

## What we DON'T ask you to do during reports

- No network fuzzing of remote endpoints in production;
- phpscan ships no proprietary secrets; you will get a local repro before
  any disclosure conversation.
