# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
("Security" tab -> "Report a vulnerability") on this repository, with steps to
reproduce and the impact you expect. You should get a first answer within 7 days.

## Scope and design notes

DNSInspector is meant to run on localhost or behind an authenticating reverse proxy.
It has no built-in authentication, so exposing it publicly lets anyone read and delete
the analysis history. The rate limiter is in-memory and per process.

The tool only sends standard DNS queries to the configured resolver, never executes
shell commands, rejects private/reserved names and non-public IPs, and stores only
public DNS data.
