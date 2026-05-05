# Security Policy

## Supported Versions

Security fixes are provided for the latest released minor version.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Do not open a public GitHub issue for suspected vulnerabilities.

Report security issues by email to:

```text
security@hciupinski.dev
```

Include:

- affected ResistanceStack version or commit,
- operating system and deployment profile,
- clear reproduction steps,
- impact and any known workaround,
- logs or output with secrets removed.

You should receive an acknowledgement within 7 days. Valid reports are triaged privately, fixed in a patch release when needed, and disclosed after a safe remediation path is available.

## Secret Handling

ResistanceStack reports and logs should not include private SSH keys, API tokens, or passwords. If you find secret disclosure in generated output, treat it as a vulnerability and report it through the private process above.
