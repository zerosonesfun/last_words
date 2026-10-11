# Protocol

Version 1 of the record format. The goal is that a service can carry encrypted bytes and signed events without being trusted to invent them.

## Roles

These keys are not interchangeable. Each signed record names its type, and verifiers check that the signature comes from the key registered for that role.

| Key | Held by | What it signs |
| --- | --- | --- |
| Message key | Split across services. A full copy is also in the owner's recovery file. | Nothing. It only opens the message. |
| Trusted person key | The trusted person | `unlock_request` |
| One-time cancel key | Emailed to the owner for that request | `cancel` for that request id |
| Recovery key | The owner, offline | `register`, `relock`, `rotate_trusted`, `rotate_recovery` |
| Service key | The service | Directory documents and key rotation. Not publication. |

A service signature does not make a message public. Publication is a conclusion any verifier can recompute.

## Message bytes

The browser encrypts with XSalsa20-Poly1305 (`nacl.secretbox` / `sodium_crypto_secretbox`). The plaintext starts with `LWMSG1`, the message id, then length-prefixed title and body. Opening the box with the wrong id is rejected, so ciphertext cannot be swapped onto another id unnoticed.

The message key is split with Shamir's scheme over GF(256), one polynomial per byte, threshold `k` of `n`. Share index 0 is never used, because that point is the secret. A leading coefficient of zero is rejected so the threshold cannot silently drop.

Each service receives only its share. The registration commits to `sha256` of every share. A service refuses a share that does not match its slot.

## Canonical records

Records are UTF-8 lines, not JSON, so PHP and the browser cannot drift on spaces or escape sequences. An event looks like this:

```
lastwords.event.v1
type=unlock_request
message_id=<32 hex chars>
request_id=<32 hex chars>
trusted_seq=1
seen_recovery_seq=0
requested_at=1700000000
deadline=1702592000
cancel_pubkey=<standard base64 of 32 bytes>
```

The signature is detached Ed25519 over those exact bytes, including the final newline. `deadline` must be `requested_at + 2592000`.

Other event types:

- `register`: message id, time, `k`, `n`, ciphertext hash, nonce, trusted public key, recovery public key, owner page, space-separated service URLs, share commitments. Signed by the recovery key named in the same record.
- `cancel`: message id, request id, time. Signed by the cancel key named in that unlock request.
- `relock`: message id, `recovery_seq`, time. Signed by the current recovery key.
- `rotate_trusted` and `rotate_recovery`: same recovery sequence, plus the new public key.

Directory documents:

```
lastwords.directory.v1
endpoint=https://example.com
sign_pubkey=<base64>
version=1.0.0
```

Service rotation:

```
lastwords.rotation.v1
old_sign_pubkey=<base64>
new_sign_pubkey=<base64>
rotated_at=<unix time>
```

Signed by the old service key.

## How state is decided

Start from the single valid registration.

Recovery events share one sequence, starting at 1. A gap stops the chain. Two different valid events with the same sequence are a conflict. The highest applied `relock` sequence is remembered.

An unlock is live only when all of this is true:

- It is signed by the trusted key that was current at `seen_recovery_seq`.
- Its trusted sequence is the next integer with no gap.
- `seen_recovery_seq` is at least the highest re-lock sequence. An older acknowledgement does not survive a newer re-lock.
- No valid cancel exists for its request id.
- The verifier's clock is at or past `deadline`.

If two different unlock bodies claim the same trusted sequence and either one is still live, the state is `conflict` and shares stay hidden. A later re-lock can supersede that pair.

Clocks do not choose a winner between events. Sequence numbers do. Clocks only answer "has this signed deadline passed?" and "is this newly submitted request close to now?"

## Acceptance window

A service stores a new unlock only if `requested_at` is within 600 seconds of its own clock. That applies to direct submissions and to copies learned from a peer. A trusted person cannot backdate a request and skip the month. A service that was offline for that window does not later adopt the request. The owner's page submits to every share holder immediately, and rolls the request back with the cancel key if one of them rejects it.

Cancellations and re-locks do not use that window on replication. A re-lock from yesterday still has to beat an older unlock.

A service releases its share only when its own log reduces to `published`. One service with a fast clock can release only its own share. A reader still needs `k` shares, and the reader's own reduction has to say `published` before those shares are used.

## What a bad service can do

It can hide data, delay mail, or release its one share early. It cannot sign an unlock, a cancel, or a re-lock for keys it does not have. The exception is the one-time cancel key that passes through the service which sends the email. That service could cancel, which keeps the message locked.

This network is not a claim of Byzantine fault tolerance. There is no vote. The owner's keys are the authority. Availability of the plaintext, once published, needs `k` honest-enough services to release shares. Learning about a re-lock needs the client to reach at least one service that has the signed event, or a peer sync that copies it.

## HTTP

Clients talk to explicit PHP files. Rewrites are not required.

- `POST /api/event.php` submits one signed event, plus the ciphertext and this service's share on registration.
- `GET /api/message.php?id=` returns the log. The share is included only when this server's log says published. Ciphertext is omitted after a re-lock.
- `GET /api/directory.php` and `GET /api/sync.php` are signed descriptions and a full log. Sync responses omit shares and email addresses.
- `POST /api/work.php` runs due work. `GET` does not.
- `POST /cron.php` with the cron key runs due work and records that cron itself ran.

GET never unlocks, cancels, publishes, or re-locks.

## Client files

`last-words-trusted.json` holds the trusted secret and the pinned service keys. `last-words-recovery.json` holds the recovery secret and the message key. `config.js` holds ciphertext, the threshold, and pinned service keys. No secret file is required for the public page to show a locked state.
