(function () {
  var app = document.getElementById('app');
  var page = document.body.getAttribute('data-page');
  if (!app || !window.nacl || !window.LastWords) {
    return;
  }
  var lw = LastWords.create(nacl);

  function el(tag, text) {
    var node = document.createElement(tag);
    if (text) node.textContent = text;
    return node;
  }

  function field(labelText, control) {
    var label = el('label', labelText);
    label.appendChild(control);
    return label;
  }

  function input(type) {
    var node = document.createElement('input');
    node.type = type;
    return node;
  }

  function button(text, fn) {
    var node = el('button', text);
    node.type = 'button';
    node.addEventListener('click', fn);
    return node;
  }

  function download(name, text) {
    var link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
    link.download = name;
    link.click();
  }

  function endpointOf(url) {
    return String(url || '').trim().replace(/\/$/, '');
  }

  function postJson(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().then(function (data) {
        if (!response.ok || !data.ok) throw new Error((data && data.error) || 'The service refused the request.');
        return data;
      });
    });
  }

  function loadService(endpoint, pinned) {
    return fetch(endpoint + '/api/directory.php').then(function (response) {
      if (!response.ok) throw new Error('unavailable');
      return response.json();
    }).then(function (document) {
      var fields = lw.verifyDirectory(document, pinned || null);
      if (!fields) throw new Error('invalid signature');
      if (endpointOf(fields.endpoint) !== endpoint) throw new Error('invalid signature');
      return { endpoint: endpoint, signPubkey: fields.sign_pubkey, document: document };
    });
  }

  function loadMessage(service, messageId) {
    return fetch(service.endpoint + '/api/message.php?id=' + encodeURIComponent(messageId)).then(function (response) {
      if (!response.ok) throw new Error('unavailable');
      return response.json();
    }).then(function (view) {
      return { service: service, view: view };
    });
  }

  function merge(results) {
    var events = [];
    var seen = {};
    results.forEach(function (result) {
      (result.view.events || []).forEach(function (event) {
        var key = event.body + event.signature;
        if (!seen[key]) {
          seen[key] = true;
          events.push(event);
        }
      });
    });
    return events;
  }

  function wordsFor(status) {
    if (status === 'locked') return 'This message is locked.';
    if (status === 'pending') return 'A publication request is waiting. The message stays private until the deadline, unless it is cancelled or re-locked.';
    if (status === 'relocked') return 'This message was re-locked. Participating services should stop handing it out. Copies that were already saved cannot be erased.';
    if (status === 'conflict') return 'The services have conflicting requests, so the message stays unavailable.';
    if (status === 'published') return 'This message is published.';
    return 'This message is not available.';
  }

  if (page === 'read') {
    var config = window.LAST_WORDS_CONFIG;
    app.appendChild(el('h1', 'Last Words'));
    if (!config) {
      app.appendChild(el('p', 'This folder does not have a message yet.'));
      var link = el('a', 'Set one up');
      link.href = 'setup.html';
      app.appendChild(link);
      return;
    }
    var report = el('p');
    app.appendChild(report);
    var title = el('h2');
    var body = el('p');
    body.className = 'message';
    var meta = el('p');
    meta.className = 'muted';
    Promise.all(config.services.map(function (service) {
      var endpoint = endpointOf(service.endpoint);
      return loadService(endpoint, service.signPubkey).then(function (checked) {
        return loadMessage(checked, config.messageId).then(function (loaded) {
          return { ok: true, loaded: loaded };
        });
      }).catch(function (error) {
        return { ok: false, endpoint: endpoint, error: error.message || 'unavailable' };
      });
    })).then(function (results) {
      var good = results.filter(function (item) { return item.ok; }).map(function (item) { return item.loaded; });
      var bad = results.filter(function (item) { return !item.ok; });
      if (!good.length) {
        report.textContent = 'No service could be verified. ' + bad.map(function (item) {
          return item.endpoint + ' (' + item.error + ')';
        }).join(', ');
        return;
      }
      var state = lw.reduce(merge(good), Math.floor(Date.now() / 1000));
      report.textContent = wordsFor(state.status);
      if (bad.length) {
        report.textContent += ' Skipped: ' + bad.map(function (item) { return item.error; }).join(', ') + '.';
      }
      if (state.status !== 'published') {
        return;
      }
      var shares = [];
      good.forEach(function (item) {
        if (item.view.share) shares.push(lw.b64decode(item.view.share));
      });
      if (shares.length < config.k) {
        report.textContent = 'The deadline has passed, but fewer than ' + config.k + ' services released a share.';
        return;
      }
      return boxMatching(state, good, config).then(function (box) {
        if (!box) {
          report.textContent = 'The latest sealed text is not on this page or on a verified service.';
          return;
        }
        openedConfig = {
          v: config.v,
          messageId: config.messageId,
          ownerPage: config.ownerPage,
          k: config.k,
          n: config.n,
          nonce: lw.b64encode(box.nonce),
          ciphertext: lw.b64encode(box.cipher),
          ciphertextSha256: state.ciphertextSha256,
          services: config.services,
          createdAt: config.createdAt
        };
        var key = lw.join(shares);
        var opened = nacl.secretbox.open(box.cipher, box.nonce, key);
        var decoded = opened ? lw.decodeMessage(opened, config.messageId) : null;
        if (!decoded) {
          report.textContent = 'The shares did not open the message.';
          return;
        }
        if (decoded.title) {
          title.textContent = decoded.title;
          app.appendChild(title);
        }
        body.textContent = decoded.body;
        app.appendChild(body);
        if (state.deadline) {
          meta.textContent = 'Published after ' + new Date(parseInt(state.deadline, 10) * 1000).toISOString().replace('.000Z', ' UTC').replace('T', ' ');
          app.appendChild(meta);
        }
      });
    }).catch(function () {
      report.textContent = 'This message is not available.';
    });
    var openedConfig = config;
    app.appendChild(button('Download encrypted copy', function () {
      download('config.js', 'window.LAST_WORDS_CONFIG = ' + JSON.stringify(openedConfig, null, 2) + ';\n');
    }));
    return;
  }

  if (page === 'setup') {
    app.appendChild(el('h1', 'Set up a Last Words message'));
    app.appendChild(el('p', 'The message is encrypted in this browser before it is sent. Give the trusted person their file, and store the recovery file somewhere else.'));
    var titleInput = input('text');
    var bodyInput = document.createElement('textarea');
    var emailInput = input('email');
    var pageInput = input('url');
    pageInput.value = location.protocol === 'http:' || location.protocol === 'https:' ? location.href.replace(/setup\.html.*$/, 'index.html') : '';
    var servicesInput = document.createElement('textarea');
    servicesInput.placeholder = 'https://example.com/last-words';
    var single = input('checkbox');
    var status = el('p');
    status.className = 'note';
    app.appendChild(field('Title, optional', titleInput));
    app.appendChild(field('Message', bodyInput));
    app.appendChild(field('Your email', emailInput));
    app.appendChild(field('Public page URL', pageInput));
    app.appendChild(field('Service URLs, one per line', servicesInput));
    var singleLabel = field('I understand that a single service can read this message, because it holds the only share.', single);
    app.appendChild(singleLabel);
    app.appendChild(status);
    var pending = null;
    var working = false;
    app.appendChild(button('Create the message', function () {
      if (working) return;
      working = true;
      status.textContent = 'Working.';
      var services = servicesInput.value.split(/\s+/).map(endpointOf).filter(Boolean);
      if (!bodyInput.value.trim() || !emailInput.value.trim() || !pageInput.value.trim() || !services.length) {
        working = false;
        status.textContent = 'Add a message, an email address, the public page, and at least one service.';
        return;
      }
      if (services.length === 1 && !single.checked) {
        working = false;
        status.textContent = 'Add another service, or confirm that you understand the single-service limit.';
        return;
      }
      var k = services.length >= 3 ? 2 : services.length;
      Promise.all(services.map(function (endpoint) { return loadService(endpoint, null); })).then(function (checked) {
        if (!pending) {
          var recovery = nacl.sign.keyPair();
          var trusted = nacl.sign.keyPair();
          var messageKey = nacl.randomBytes(32);
          var messageId = Array.from(nacl.randomBytes(16)).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
          var shares = lw.split(messageKey, k, services.length);
          var nonce = nacl.randomBytes(24);
          var plain = lw.encodeMessage(messageId, titleInput.value.trim(), bodyInput.value);
          var cipher = nacl.secretbox(plain, nonce, messageKey);
          return sha256(shares).then(function (digests) {
            var fields = {
              message_id: messageId,
              created_at: String(Math.floor(Date.now() / 1000)),
              k: String(k),
              n: String(services.length),
              ciphertext_sha256: '',
              nonce: lw.b64encode(nonce),
              trusted_pubkey: lw.b64encode(trusted.publicKey),
              recovery_pubkey: lw.b64encode(recovery.publicKey),
              owner_page: pageInput.value.trim(),
              services: services.join(' '),
              share_commitments: digests.map(function (digest, index) { return (index + 1) + ':' + digest; }).join(',')
            };
            return sha256([concat([nonce, cipher])]).then(function (sum) {
              fields.ciphertext_sha256 = sum[0];
              var body = lw.build('register', fields);
              var signature = lw.b64encode(nacl.sign.detached(lw.utf8(body), recovery.secretKey));
              pending = {
                fields: fields,
                body: body,
                signature: signature,
                signer: lw.b64encode(recovery.publicKey),
                cipher: cipher,
                nonce: nonce,
                shares: shares,
                recovery: recovery,
                trusted: trusted,
                messageKey: messageKey,
                checked: checked
              };
              return sendPending();
            });
          });
        }
        return sendPending();
      }).catch(function (error) {
        working = false;
        status.textContent = error.message || 'Setup stopped.';
      });

      function sendPending() {
        return Promise.all(pending.checked.map(function (service, index) {
          return postJson(service.endpoint + '/api/event.php', {
            body: pending.body,
            signature: pending.signature,
            signer_public: pending.signer,
            ciphertext: lw.b64encode(pending.cipher),
            nonce: lw.b64encode(pending.nonce),
            share: lw.b64encode(pending.shares[index]),
            owner_email: emailInput.value.trim()
          });
        })).then(function () {
          return Promise.all(pending.checked.map(function (service) {
            return loadMessage(service, pending.fields.message_id);
          }));
        }).then(function (views) {
          views.forEach(function (item) {
            if (item.view.state !== 'locked' || item.view.share || item.view.ciphertext_sha256 !== pending.fields.ciphertext_sha256) {
              throw new Error('A service did not confirm the locked message.');
            }
          });
          var config = {
            v: 1,
            messageId: pending.fields.message_id,
            ownerPage: pending.fields.owner_page,
            k: parseInt(pending.fields.k, 10),
            n: parseInt(pending.fields.n, 10),
            nonce: lw.b64encode(pending.nonce),
            ciphertext: lw.b64encode(pending.cipher),
            ciphertextSha256: pending.fields.ciphertext_sha256,
            services: pending.checked.map(function (service) {
              return { endpoint: service.endpoint, signPubkey: service.signPubkey };
            }),
            createdAt: pending.fields.created_at
          };
          download('config.js', 'window.LAST_WORDS_CONFIG = ' + JSON.stringify(config, null, 2) + ';\n');
          download('last-words-trusted.json', JSON.stringify({
            kind: 'lastwords-trusted',
            v: 1,
            warning: 'This file can request publication. It cannot read the message by itself. Give it only to the trusted person.',
            message_id: pending.fields.message_id,
            owner_page: pending.fields.owner_page,
            unlock_page: pending.fields.owner_page.replace(/index\.html$/, 'unlock.html'),
            trusted_public: lw.b64encode(pending.trusted.publicKey),
            trusted_secret: lw.b64encode(pending.trusted.secretKey),
            services: config.services
          }, null, 2));
          download('last-words-recovery.json', JSON.stringify({
            kind: 'lastwords-recovery',
            v: 1,
            warning: 'This file can read the message and re-lock it. Keep it apart from the trusted person file.',
            message_id: pending.fields.message_id,
            owner_page: pending.fields.owner_page,
            recovery_public: lw.b64encode(pending.recovery.publicKey),
            recovery_secret: lw.b64encode(pending.recovery.secretKey),
            message_key: lw.b64encode(pending.messageKey),
            services: config.services,
            created_at: pending.fields.created_at
          }, null, 2));
          status.textContent = 'Locked, and each service accepted it. Save the three downloads. Upload config.js next to index.html. The recovery file is not on the server.';
        });
      }
    }));
    return;
  }

  function readSecretFile(fileInput, textInput) {
    if (fileInput.files && fileInput.files[0]) {
      return fileInput.files[0].text();
    }
    return Promise.resolve(textInput.value);
  }

  if (page === 'unlock') {
    app.appendChild(el('h1', 'Request publication'));
    app.appendChild(el('p', 'This starts a 30 day wait. It does not show the message. The owner gets an email and can cancel. Open this page from the owner\'s website, or from the copy saved at setup, rather than from a form run by a service.'));
    var fileInput = input('file');
    var textInput = document.createElement('textarea');
    var status = el('p');
    status.className = 'note';
    app.appendChild(field('Trusted person file', fileInput));
    app.appendChild(field('Or paste the file', textInput));
    app.appendChild(status);
    app.appendChild(button('Confirm publication request', function () {
      status.textContent = 'Checking services.';
      readSecretFile(fileInput, textInput).then(function (raw) {
        var trusted = JSON.parse(raw);
        if (trusted.kind !== 'lastwords-trusted' || !trusted.trusted_secret) throw new Error('That is not a trusted person file.');
        var secret = lw.b64decode(trusted.trusted_secret);
        if (!secret) throw new Error('The trusted person key could not be read.');
        return Promise.all(trusted.services.map(function (service) {
          return loadService(endpointOf(service.endpoint), service.signPubkey).then(function (checked) {
            return loadMessage(checked, trusted.message_id);
          });
        })).then(function (views) {
          var state = lw.reduce(merge(views), Math.floor(Date.now() / 1000));
          if (state.status === 'pending' || state.status === 'published' || state.status === 'conflict') {
            throw new Error(wordsFor(state.status));
          }
          var cancel = nacl.sign.keyPair();
          var now = Math.floor(Date.now() / 1000);
          var fields = {
            message_id: trusted.message_id,
            request_id: hexId(),
            trusted_seq: String(state.nextTrustedSeq || 1),
            seen_recovery_seq: String(state.recoverySeq || 0),
            requested_at: String(now),
            deadline: String(now + lw.UNLOCK_WINDOW),
            cancel_pubkey: lw.b64encode(cancel.publicKey)
          };
          var body = lw.build('unlock_request', fields);
          var payload = {
            body: body,
            signature: lw.b64encode(nacl.sign.detached(lw.utf8(body), secret)),
            signer_public: lw.b64encode(lw.publicFromSecret(secret)),
            cancel_secret: lw.b64encode(cancel.secretKey)
          };
          var accepted = [];
          return views.reduce(function (chain, item) {
            return chain.then(function () {
              return postJson(item.service.endpoint + '/api/event.php', payload).then(function () {
                accepted.push(item.service.endpoint);
              });
            });
          }, Promise.resolve()).catch(function (error) {
            var cancelBody = lw.build('cancel', {
              message_id: trusted.message_id,
              request_id: fields.request_id,
              cancelled_at: String(Math.floor(Date.now() / 1000))
            });
            var cancelPayload = {
              body: cancelBody,
              signature: lw.b64encode(nacl.sign.detached(lw.utf8(cancelBody), cancel.secretKey)),
              signer_public: lw.b64encode(cancel.publicKey)
            };
            return Promise.all(accepted.map(function (endpoint) {
              return postJson(endpoint + '/api/event.php', cancelPayload).catch(function () {});
            })).then(function () {
              throw new Error((error.message || 'A service did not accept the request.') + ' Any service that had accepted it was asked to cancel.');
            });
          }).then(function () {
            status.textContent = 'The request is in. The owner has 30 days to cancel it. You can close this page.';
          });
        });
      }).catch(function (error) {
        status.textContent = error.message || 'The request was not sent.';
      });
    }));
    return;
  }

  if (page === 'recover') {
    app.appendChild(el('h1', 'Emergency re-lock'));
    app.appendChild(el('p', 'Use the recovery file, not the trusted person file. This works without the email account. Re-locking stops participating services from handing the message out. It cannot erase copies someone already saved.'));
    var fileInput = input('file');
    var textInput = document.createElement('textarea');
    var status = el('p');
    status.className = 'note';
    app.appendChild(field('Recovery file', fileInput));
    app.appendChild(field('Or paste the file', textInput));
    app.appendChild(status);
    app.appendChild(button('Re-lock the message', function () {
      withRecovery(fileInput, textInput, status, function (record, views, secret) {
        var state = lw.reduce(merge(views), Math.floor(Date.now() / 1000));
        var fields = {
          message_id: record.message_id,
          recovery_seq: String(state.nextRecoverySeq || 1),
          relocked_at: String(Math.floor(Date.now() / 1000))
        };
        var body = lw.build('relock', fields);
        var payload = {
          body: body,
          signature: lw.b64encode(nacl.sign.detached(lw.utf8(body), secret)),
          signer_public: lw.b64encode(lw.publicFromSecret(secret))
        };
        return Promise.all(views.map(function (item) {
          return postJson(item.service.endpoint + '/api/event.php', payload).then(function () {
            return true;
          }).catch(function () {
            return false;
          });
        })).then(function (results) {
          var good = results.filter(Boolean).length;
          status.textContent = 'Re-lock accepted by ' + good + ' of ' + results.length + ' services. Retry if that is not all of them.';
        });
      });
    }));
    app.appendChild(el('h2', 'Rewrite the message'));
    app.appendChild(el('p', 'The same recovery file can replace the words. The key stays the same, so this file and the trusted person file keep working. Upload the new config.js when the page downloads it.'));
    var editTitle = input('text');
    var editBody = document.createElement('textarea');
    app.appendChild(field('Title', editTitle));
    app.appendChild(field('Message', editBody));
    app.appendChild(button('Show the current words', function () {
      withRecovery(fileInput, textInput, status, function (record, views) {
        var state = lw.reduce(merge(views), Math.floor(Date.now() / 1000));
        var key = lw.b64decode(record.message_key);
        if (!key) throw new Error('The recovery file does not include the message key.');
        return boxMatching(state, views, null).then(function (box) {
          if (!box) throw new Error('No service returned the latest sealed text.');
          var opened = nacl.secretbox.open(box.cipher, box.nonce, key);
          var decoded = opened ? lw.decodeMessage(opened, record.message_id) : null;
          if (!decoded) throw new Error('The recovery file did not open the message.');
          editTitle.value = decoded.title;
          editBody.value = decoded.body;
          status.textContent = 'These are the current words. Change them, then save.';
        });
      });
    }));
    app.appendChild(button('Save the new words', function () {
      withRecovery(fileInput, textInput, status, function (record, views, secret) {
        var state = lw.reduce(merge(views), Math.floor(Date.now() / 1000));
        var key = lw.b64decode(record.message_key);
        if (!key) throw new Error('The recovery file does not include the message key.');
        if (lw.utf8(editTitle.value).length > 200) throw new Error('The title is too long.');
        if (lw.utf8(editBody.value).length > 65536) throw new Error('The message is too long.');
        var plain = lw.encodeMessage(record.message_id, editTitle.value.trim(), editBody.value);
        var nonce = nacl.randomBytes(24);
        var cipher = nacl.secretbox(plain, nonce, key);
        return sha256Bytes(concat([nonce, cipher])).then(function (sum) {
          var fields = {
            message_id: record.message_id,
            recovery_seq: String(state.nextRecoverySeq || 1),
            revised_at: String(Math.floor(Date.now() / 1000)),
            ciphertext_sha256: sum,
            nonce: lw.b64encode(nonce)
          };
          var body = lw.build('revise', fields);
          var payload = {
            body: body,
            signature: lw.b64encode(nacl.sign.detached(lw.utf8(body), secret)),
            signer_public: lw.b64encode(lw.publicFromSecret(secret)),
            ciphertext: lw.b64encode(cipher),
            nonce: lw.b64encode(nonce)
          };
          return Promise.all(views.map(function (item) {
            return postJson(item.service.endpoint + '/api/event.php', payload).then(function () {
              return true;
            }).catch(function () {
              return false;
            });
          })).then(function (results) {
            var good = results.filter(Boolean).length;
            if (!good) throw new Error('No service accepted the new words.');
            var sample = views[0].view;
            var config = {
              v: 1,
              messageId: record.message_id,
              ownerPage: sample.owner_page || record.owner_page,
              k: sample.k,
              n: sample.n,
              nonce: lw.b64encode(nonce),
              ciphertext: lw.b64encode(cipher),
              ciphertextSha256: sum,
              services: record.services,
              createdAt: record.created_at
            };
            download('config.js', 'window.LAST_WORDS_CONFIG = ' + JSON.stringify(config, null, 2) + ';\n');
            status.textContent = 'Saved on ' + good + ' of ' + results.length + ' services. Upload the new config.js. The recovery file did not change.';
          });
        });
      });
    }));
    app.appendChild(button('Create a new recovery key', function () {
      withRecovery(fileInput, textInput, status, function (record, views, secret) {
        var state = lw.reduce(merge(views), Math.floor(Date.now() / 1000));
        var next = nacl.sign.keyPair();
        var fields = {
          message_id: record.message_id,
          recovery_seq: String(state.nextRecoverySeq || 1),
          new_recovery_pubkey: lw.b64encode(next.publicKey),
          rotated_at: String(Math.floor(Date.now() / 1000))
        };
        var body = lw.build('rotate_recovery', fields);
        var payload = {
          body: body,
          signature: lw.b64encode(nacl.sign.detached(lw.utf8(body), secret)),
          signer_public: lw.b64encode(lw.publicFromSecret(secret))
        };
        return Promise.all(views.map(function (item) {
          return postJson(item.service.endpoint + '/api/event.php', payload);
        })).then(function () {
          record.recovery_public = lw.b64encode(next.publicKey);
          record.recovery_secret = lw.b64encode(next.secretKey);
          record.warning = 'This file replaces the previous recovery file. The old one no longer works.';
          download('last-words-recovery.json', JSON.stringify(record, null, 2));
          status.textContent = 'The new recovery file was downloaded. Store it, and retire the old one.';
        });
      });
    }));
  }

  function withRecovery(fileInput, textInput, status, action) {
    status.textContent = 'Checking services.';
    readSecretFile(fileInput, textInput).then(function (raw) {
      var record = JSON.parse(raw);
      if (record.kind !== 'lastwords-recovery' || !record.recovery_secret) throw new Error('That is not a recovery file.');
      var secret = lw.b64decode(record.recovery_secret);
      if (!secret) throw new Error('The recovery key could not be read.');
      return Promise.all(record.services.map(function (service) {
        return loadService(endpointOf(service.endpoint), service.signPubkey).then(function (checked) {
          return loadMessage(checked, record.message_id);
        });
      })).then(function (views) {
        return action(record, views, secret);
      });
    }).catch(function (error) {
      status.textContent = error.message || 'The recovery action was not sent.';
    });
  }

  function hexId() {
    return Array.from(nacl.randomBytes(16)).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  function concat(parts) {
    var size = parts.reduce(function (sum, part) { return sum + part.length; }, 0);
    var out = new Uint8Array(size);
    var offset = 0;
    parts.forEach(function (part) {
      out.set(part, offset);
      offset += part.length;
    });
    return out;
  }

  function boxMatching(state, views, local) {
    var want = state.ciphertextSha256;
    var candidates = [];
    if (local && local.ciphertextSha256 === want) {
      candidates.push({ nonce: lw.b64decode(local.nonce), cipher: lw.b64decode(local.ciphertext) });
    }
    views.forEach(function (item) {
      if (!item.view || item.view.ciphertext_sha256 !== want || !item.view.ciphertext) return;
      candidates.push({ nonce: lw.b64decode(item.view.nonce), cipher: lw.b64decode(item.view.ciphertext) });
    });
    var chain = Promise.resolve(null);
    candidates.forEach(function (item) {
      chain = chain.then(function (found) {
        if (found || !item.nonce || !item.cipher) return found;
        return sha256Bytes(concat([item.nonce, item.cipher])).then(function (sum) {
          return sum === want ? item : found;
        });
      });
    });
    return chain;
  }

  function sha256Bytes(bytes) {
    return crypto.subtle.digest('SHA-256', bytes).then(function (buffer) {
      return Array.from(new Uint8Array(buffer)).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    });
  }

  function sha256(parts) {
    return Promise.all(parts.map(function (part) {
      return crypto.subtle.digest('SHA-256', part).then(function (buffer) {
        return Array.from(new Uint8Array(buffer)).map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
      });
    }));
  }
})();
