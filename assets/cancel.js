(function () {
  var status = document.getElementById('cancel-status');
  var button = document.getElementById('cancel-go');
  if (!status || !button || !window.nacl || !window.LastWords) {
    return;
  }
  var lw = LastWords.create(nacl);
  var hash = new URLSearchParams((location.hash || '').replace(/^#/, ''));
  var messageId = hash.get('m') || '';
  var requestId = hash.get('r') || '';
  var secretB64 = hash.get('k') || '';

  function say(text) {
    status.textContent = text;
  }

  if (!/^[a-f0-9]{32}$/.test(messageId) || !/^[a-f0-9]{32}$/.test(requestId) || secretB64 === '') {
    say('Open the link from the email again. The cancellation key was not in this page address.');
    button.hidden = true;
    return;
  }

  button.addEventListener('click', function () {
    button.disabled = true;
    say('Contacting services.');
    var secret = lw.b64decode(decodeURIComponent(secretB64));
    if (!secret || secret.length !== 64) {
      say('The cancellation key from the email could not be read.');
      return;
    }
    fetch('api/message.php?id=' + encodeURIComponent(messageId), { credentials: 'omit' })
      .then(function (response) { return response.json(); })
      .then(function (view) {
        if (!view || !view.events) {
          throw new Error('This service does not have that request.');
        }
        var services = [];
        view.events.forEach(function (event) {
          try {
            var parsed = lw.parse(event.body);
            if (parsed.type === 'register') {
              services = parsed.fields.services.split(' ');
            }
          } catch (ignore) {}
        });
        if (!services.length) {
          services = [location.origin + location.pathname.replace(/\/cancel\.php$/, '')];
        }
        var fields = {
          message_id: messageId,
          request_id: requestId,
          cancelled_at: String(Math.floor(Date.now() / 1000))
        };
        var body = lw.build('cancel', fields);
        var signature = lw.b64encode(nacl.sign.detached(lw.utf8(body), secret));
        var signer = lw.b64encode(secret.slice(32));
        var payload = JSON.stringify({
          body: body,
          signature: signature,
          signer_public: signer
        });
        return Promise.all(services.map(function (endpoint) {
          return fetch(endpoint.replace(/\/$/, '') + '/api/event.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload
          }).then(function (response) {
            return response.json().then(function (data) {
              return { ok: response.ok && data && data.ok, error: data && data.error };
            });
          }).catch(function () {
            return { ok: false, error: 'unreachable' };
          });
        }));
      })
      .then(function (results) {
        var good = results.filter(function (item) { return item.ok; }).length;
        if (good === 0) {
          say(results[0] && results[0].error ? results[0].error : 'No service accepted the cancellation.');
          button.disabled = false;
          return;
        }
        say('Cancelled on ' + good + ' of ' + results.length + ' services. The message stays private. The trusted person can make a new request later.');
        button.hidden = true;
      })
      .catch(function (error) {
        say(error.message || 'The cancellation could not be sent.');
        button.disabled = false;
      });
  });
})();
