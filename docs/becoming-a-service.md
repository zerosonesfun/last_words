# Become a service

A service stores ciphertext, one share of each message key it was given, and the signed event log. It sends notification email. It does not grant you the ability to publish, cancel, re-lock, or rewrite someone else's message. Those actions need signatures from keys you do not hold. A rewrite keeps the same message key, so if you already hold every share you can read the new words too.

You do not need approval from the author of this software. Install the same release, from the same browser installer, on your own host. The public page `become.php` on every service repeats this.

Independent services matter because a person's page can keep working when one host disappears, and because a locked message should not be readable by a single operator. That second part is only true when the owner picked a threshold greater than one. Say so if someone asks you to be their only service.

## What you can see

Message ids, ciphertext, your share, public keys, and the owner's email address when they named your service. You need the address to send mail. The database copy of the address and of queued mail is encrypted with the service storage key. The admin backup is encrypted again with a password you choose at download time.

When your service emails a cancellation link, it sees that one-time cancellation key long enough to put it in the mail queue. A dishonest operator could cancel that request. Cancellation keeps the message locked. It does not reveal the text.

## Peers

Add peers from the admin page. Last Words fetches the signed directory and stores the public key. Later syncs reject a response that is not signed by that key, or by a key the old one explicitly rotated to.

A message's service list does not make your server contact those URLs on its own. You choose peers. The owner's browser delivers events to each service directly. Peer sync is how a service that was offline catches a cancellation or a re-lock afterward.

Sync of a new unlock is only accepted if this server sees it within about 10 minutes of the signed request time. That stops a peer from delivering a backdated unlock that would skip the wait. Cancellations and re-locks are accepted later, because an old re-lock must still be able to win.

## Leaving

Tell peer operators to drop your URL. Leave the machine up until their sync has run, if you can. Deleting your server deletes your share and your copy of the log. It does not delete anyone else's copy.

## Updates

Replace the program files from a release. Keep the data directory. The admin page shows the version and links to the repository. It does not phone home.
