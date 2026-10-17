# Contributing

Bugs and patches are welcome. Keep changes small enough that another PHP developer can review them without a walkthrough.

- Run `php tests/run.php` before you send a change.
- Do not add a framework, a build step, or a new service dependency unless the installer can still run on shared hosting without Composer.
- Prefer a few clear functions over a new abstraction.
- Comments should say why something is easy to get wrong. Skip comments that restate the next line.
- Do not use em dashes or en dashes in code, comments, docs, or interface text.
- Do not claim a behavior works unless a test covers it.

Security reports go through [SECURITY.md](SECURITY.md), not the public issue list.

Vendor updates: replace `lib/phpmailer/` from the pinned PHPMailer release, or `client/vendor/nacl.js` from TweetNaCl.js 1.0.3, then copy `nacl.js` to `assets/nacl.js`. Copy `client/protocol.js` to `assets/protocol.js` as well. The test suite checks that those copies match.
