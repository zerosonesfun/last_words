# Last Words

I want a way to leave a private message on my own website, and to name one person who can ask for it to be published after I die.

The message should not sit on the page in the clear. The trusted person gets their own file. Using it does not open the message. It starts a wait of 30 days. During that time I can cancel by email. If I do nothing, the message can be published.

I also want a second file, a recovery key, kept somewhere else. That one can lock the message again if it goes out by mistake. It cannot erase a copy someone already saved.

This does not know whether I have died. It only follows the files.

A service holds the sealed message and one share of the key. With one service, that share is the whole key. With more than one, the page needs enough shares before the words appear. Editing the service database cannot publish the message. Publication follows signed events, and the service does not hold the keys that sign an unlock, a cancel, or a re-lock.

The sketch of the personal file is in [examples/last-words.json](examples/last-words.json). The record format is in [docs/protocol.md](docs/protocol.md).

## How it will work:

![How it will work](examples/how-it-works.jpg)
