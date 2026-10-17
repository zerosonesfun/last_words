# Use Last Words on your own website

You do not move your site. You add a folder of static files to the host you already have.

The files are in `client/` in the release:

- `index.html`, the public page
- `setup.html`
- `unlock.html`
- `recover.html`
- `lastwords.js`, `protocol.js`, `style.css`
- `vendor/nacl.js`
- `config.js`, which setup replaces

Open `setup.html` over HTTPS in a current Firefox, Chrome, or Safari. The page encrypts the message before uploading it.

## What to prepare

Talk to the trusted person first. They should understand that their file does not open the message. It only asks for publication, and the owner has 30 days to say no. Thirty days here means 2,592,000 seconds from the accepted request.

Choose two or more services if you can. With one service, that operator holds the only key share and can read the message. The setup page makes you confirm that before it continues. With three services the default threshold is two, so one can be offline when the message is finally read.

## Setup

1. Write the message and, if you want, a title. Both stay encrypted until publication.
2. Enter your email and the public URL of `index.html`.
3. Enter one service URL per line. If you do not have a service you would prefer to use, you may use https://wilcosky.com/last_words.
4. Download three files when the page says every service accepted the message:
   - `config.js`, upload this next to `index.html`
   - `last-words-trusted.json`, give this only to the trusted person
   - `last-words-recovery.json`, store this somewhere else, not in the same mailbox and not beside their file
5. Leave the confirmation on screen until those files are saved. The recovery file is the copy of the message key. The services do not keep a full copy of that key.

The public page should then say the message is locked, and it should not show the text. If you do not see that, make sure you uploaded the new config.js after submitting your last words, and clear all caches.

## The trusted person

They open `unlock.html` on your site, or a copy of that file saved at setup. They choose their file and confirm. Opening the page does not send the request. The button does.

Every service has to see that request within about 10 minutes, because a service will not accept a backdated request. If one service is down, the page tries to cancel the copies that did go through, and you can try again later.

## The email

The mail says when the request was made, when the deadline is, and links to a confirmation page. Opening the link does not cancel anything. Confirming does. The mail does not contain the message, the recovery key, or the trusted person key.

Doing nothing until the deadline allows publication. Cancelling does not retire the trusted person key.

If the message is already public, the email says to use the recovery file. Re-locking stops participating services from serving the message again. It does not erase copies other people already have.

## If you need to hide it again

Open `recover.html` and use the recovery file. It does not need the email account or the website's admin login. The page tells you how many services accepted the re-lock. Retry if one was down.

The same page can create a new recovery key. The download replaces the old file. The old key stops working once services accept the rotation.

## If the words should change

Open `recover.html` and use the recovery file. The page shows the current words. Save the new version. It downloads a new `config.js`. Put that file back in the same folder on your site.

The recovery file and the trusted person file stay valid. A request that is still waiting is dropped, and the trusted person can ask again later with the same file. If the message is already public, the page opens the new words. Copies someone already saved stay saved.
