# Security and limits

Last Words is a careful mailbox for a message, plus a delay. It is not a way to prove a death, and it is not a promise that a published sentence can be recalled.

## What the design holds

- Locked plaintext is not stored. Tests check the database and the API for the original text.
- Shares use a threshold. Below `k`, the key does not come back.
- Unlock, cancel, re-lock, and rewrite need the key registered for that action. A service database edit does not create a valid signature. A rewrite keeps the message key, so an operator who already holds every share can read the new words.
- GET does not move the state machine.
- Admin forms use a session token. The API does not use cookies. The signature is the authorization.
- SQL uses prepared statements. Message ids are 32 hex characters. Paths are not taken from request fields.
- The installer refuses to finish when a private-file probe can be downloaded, or when a required PHP feature is missing. The default data directory is beside the program and is blocked by `.htaccess`.
- Rate limits apply to sign-in, reset, and event submission.
- Pages escape text. The public message is inserted with `textContent`.
- Error pages do not print paths, queries, or stack traces. Details go to `error.log` in the private directory.
- Production state changes require HTTPS. Localhost is exempt so tests can run.
- Repeated scheduler runs key publication mail on the request id, so the same deadline does not send a second "it is public" letter.
- A re-lock with a higher recovery sequence supersedes an older pending or published unlock. The scheduler pulls peers before it sends publication mail, so a replica that is behind can learn the re-lock first.

## What it does not hold

- It cannot tell whether the owner has died. A trusted person can start the clock whenever they decide to.
- Email can be missed, delayed, or read by someone who took over the account. A stolen mailbox can cancel a request. It cannot, by itself, publish or read the message. The recovery key does not depend on the mailbox.
- The service that sends the cancellation email sees that one-time key. It could cancel. It still cannot publish.
- A single-service setup lets that operator read the message. The setup page says so.
- Re-locking deletes this server's share from public responses and asks peers to do the same. Anyone who already copied the text, the picture, or a cache still has it.
- A service can go silent or lie that it is down. Clients are supposed to try the next pinned service and ignore a bad signature. They cannot invent missing shares.
- Two services that accepted different unlock requests for the same sequence end in `conflict` and do not release shares once both events are in one log. Until they sync, each might still believe its own request. The owner's client submits one request to all of them and cancels if the set does not accept it.
- Peer sync will not adopt an unlock that this server first sees more than about 10 minutes after `requested_at`. That is deliberate. A restored server whose backup predates the request will not release a share for it.
- Clocks should be within a few minutes of UTC. The signed deadline is absolute. A badly wrong clock can refuse a fresh request or withhold a share until the clock catches up.
- The admin operator can read the data directory, including their own share and the SMTP password. Encrypt the backup, and do not leave `config.php` in a public folder.
- Queued email is encrypted at rest and wiped after a successful send. A failed queue still holds the body, including a cancellation link, until it is sent or abandoned after eight attempts.
- This is not a claim that the network tolerates arbitrary malicious majorities. Read the trust limits in [protocol.md](protocol.md).

## Dependencies

- PHPMailer 6.9.3, LGPL-2.1, in `lib/phpmailer/`.
- TweetNaCl.js 1.0.3, public domain, in `client/vendor/nacl.js`.

## Passwords and tokens

Admin passwords and reset tokens are stored with `password_hash`. The cron key and SMTP password live in the private config file. Shares, owner email, and queued mail bodies are secretbox-encrypted with the storage key beside the database. Logs are not given the submitted secrets. Failure rows store a short reason, not the request body.
