# Backup, moving, and re-locking

## Operator backup

On the admin page, choose a backup password and download the file. It is a secretbox around the config, the SQLite database, the service signing key, the storage key, and the install flag. The password is stretched with Argon2id. A wrong password does not open the file.

The download is still sensitive. It contains enough to impersonate the service and to read the shares this server holds. Store it like a password manager export.

Restore from the admin page by uploading the file, entering the password, and typing RESTORE. You can also restore onto an empty data directory and then point the site at it. After a restore, reload the admin page. If the public URL changed, edit `public_url` in the private `config.php` and tell people who listed the old address.

Take a backup before you rotate the service key or move hosts.

## Service key rotation

The admin page generates a new signing key, and the old key signs a rotation record first. Clients that pinned the old key follow that record. The previous private key is not kept.

If you lose the private key and have no backup, you cannot prove a rotation. Peers that pinned the old key should drop you. Owners would need to set the message up again with a new service.

## Owner recovery

The recovery file from setup can re-lock the message, replace the sealed text, and mint a replacement recovery key. It also contains the message key, so the owner can still read their own text after shares are deleted. Saving new words requires that file. The page alone is not enough.

Use `recover.html` on the owner's site. The ordinary website login is not required. If that site is gone, open a saved copy of `recover.html`, `protocol.js`, `lastwords.js`, and `vendor/nacl.js` together. The file lists the service URLs.

Re-lock is accepted or it is not. The page counts how many services took it. An old publication job must not undo it: the re-lock has a higher recovery sequence, and schedulers pull peers before they send a publication notice.

Re-locking does not erase copies that already left the network.

## If email never arrives

The request can still be pending. The admin page shows mail failures. Temporary SMTP errors are retried at 1 minute, 5 minutes, 15 minutes, 1 hour, and 6 hours, then marked failed. Publication does not wait for the letter. The letter is a warning, not the lock.

The owner who never sees the mail can still re-lock with the recovery file if they have it.

## Removing a service

Drop the peer on the other servers. Shut down only after those syncs have had a chance to copy events you were the only one holding, especially a recent re-lock or cancellation. Your share disappears with the server. Other services keep theirs.
