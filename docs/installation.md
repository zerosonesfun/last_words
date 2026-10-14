# Install a service

This is the path for a conventional PHP host, including the first service on a site you already control. You do not need a terminal.

## Before you upload

The host needs:

- PHP 8.2 or newer
- PDO SQLite
- The Sodium extension, including signatures and secretbox
- OpenSSL
- JSON
- HTTPS on the public address (localhost is the only plain HTTP exception, and it is for testing)
- `allow_url_fopen` or curl, so you can add peers later
- A place to put private files that the web server will not hand out
- SMTP for outgoing mail
- A hosting cron job that can send a POST request

The installer checks these. If one is missing it stops. It does not fall back to a weaker mode.

Point the domain at the `public` folder when the host allows a document root. If the whole project sits inside the web root, the private data directory must still be somewhere else, or protected so thoroughly that the installer cannot download a test file from it.

## Steps

1. Download the release zip from the source repository.
2. Upload it and extract it with the hosting file manager.
3. Visit `install/` in a browser.
4. Read every check. A row marked Stop means you should fix the host before continuing.
5. Enter the public URL, the operator email, SMTP settings, and the private data directory.
6. Click Install. The page sends a test email before it finishes.
7. Save the admin password, the reset token, and the cron key from the success page. They are not shown again.
8. In the hosting panel, schedule a POST. The success page shows the exact command, in this shape:

```
curl -fsS -X POST -d "key=YOUR_CRON_KEY" https://example.com/cron.php
```

A normal visit to `cron.php` does nothing, on purpose. Link scanners must not be able to publish a message.

If the host cannot POST on a schedule, say so to yourself honestly: publication can still run when a browser POSTs to `api/work.php`, and that is not a guarantee. The admin page stays on "cron has not run" until a real cron POST arrives.

9. Open the admin page and confirm the public key, mail status, and storage line.

Visiting `install/` after a finished install returns a generic not found page. It does not print the configuration. If you copy the installer file back, the `INSTALLED` flag in the data directory still blocks a second install.

## Afterward

Add at least one peer if you know another service. Read [recovery](recovery.md) and take an encrypted backup once mail and the cron line look right.
