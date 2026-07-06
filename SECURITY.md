# Security Policy

action-locker is a security tool, so we hold it to the standard it holds
others to. The entire tool is one stdlib-only Python file — we encourage
you to read it before you run it.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, or by email to security@oldwell-labs.com.

Please do not open public issues for suspected vulnerabilities.

We will acknowledge reports within 3 business days.

## Scope notes

Things we consider in scope:

- Ways a malicious workflow file, lockfile, or vendored tree could cause
  `verify` to pass when it should fail (verification bypass)
- Argument/option injection into the `git`, `curl`, or `tar` subprocesses
- Ways `lock`/`vendor` could be tricked into resolving or fetching content
  from a repository other than the one named in the workflow

Known, documented limitations (see README "What it does not protect
against") are not vulnerabilities — but if you can turn one into a
practical attack we absolutely want to hear about it.
