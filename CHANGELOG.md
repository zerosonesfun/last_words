# Changelog

## 1.0.0

First public release.

- Browser installer for a single PHP host, with a compatibility check that stops rather than weakening the setup.
- Encrypted messages, Shamir shares, the 30 day unlock workflow, cancellation, and emergency re-lock.
- A signed event log that services can replicate. Clients verify signatures and try the next service when one is down or invalid.
- Encrypted operator backups, service key rotation, and the static client for a personal website.
- A later rewrite of the sealed text. The message key stays the same, and the recovery file is required.
