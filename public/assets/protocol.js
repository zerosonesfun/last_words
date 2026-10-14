// Browser helpers for the line format the PHP service signs.
// The bytes have to match src/Protocol.php and src/State.php.
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  }
  if (root) {
    root.LastWords = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  var FIELDS = {
    register: ['message_id', 'created_at', 'k', 'n', 'ciphertext_sha256', 'nonce', 'trusted_pubkey', 'recovery_pubkey', 'owner_page', 'services', 'share_commitments'],
    unlock_request: ['message_id', 'request_id', 'trusted_seq', 'seen_recovery_seq', 'requested_at', 'deadline', 'cancel_pubkey'],
    cancel: ['message_id', 'request_id', 'cancelled_at'],
    relock: ['message_id', 'recovery_seq', 'relocked_at'],
    rotate_trusted: ['message_id', 'recovery_seq', 'trusted_pubkey', 'rotated_at'],
    rotate_recovery: ['message_id', 'recovery_seq', 'new_recovery_pubkey', 'rotated_at'],
    revise: ['message_id', 'recovery_seq', 'revised_at', 'ciphertext_sha256', 'nonce']
  };
  var UNLOCK_WINDOW = 2592000;

  function create(nacl) {
    function b64encode(bytes) {
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin);
    }

    function b64decode(text) {
      if (typeof text !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return null;
      var bin;
      try {
        bin = atob(text);
      } catch (error) {
        return null;
      }
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      if (b64encode(out) !== text) return null;
      return out;
    }

    function utf8(text) {
      return new TextEncoder().encode(text);
    }

    function fromUtf8(bytes) {
      return new TextDecoder().decode(bytes);
    }

    function same(left, right) {
      if (!left || !right || left.length !== right.length || left.length === 0) return false;
      return nacl.verify(left, right);
    }

    function build(type, fields) {
      var names = FIELDS[type];
      if (!names) throw new Error('Unknown event type.');
      var lines = ['lastwords.event.v1', 'type=' + type];
      names.forEach(function (name) {
        if (fields[name] === undefined || fields[name] === null) throw new Error('Event is missing a field.');
        lines.push(name + '=' + String(fields[name]));
      });
      return lines.join('\n') + '\n';
    }

    function parse(body) {
      if (!body.endsWith('\n') || body.indexOf('\r') !== -1) throw new Error('Event is malformed.');
      var lines = body.slice(0, -1).split('\n');
      if (lines.length < 2 || lines[0] !== 'lastwords.event.v1' || lines[1].indexOf('type=') !== 0) {
        throw new Error('Event is malformed.');
      }
      var type = lines[1].slice(5);
      var names = FIELDS[type];
      if (!names || lines.length !== 2 + names.length) throw new Error('Event is malformed.');
      var fields = {};
      names.forEach(function (name, index) {
        var prefix = name + '=';
        if (lines[index + 2].indexOf(prefix) !== 0) throw new Error('Event is malformed.');
        fields[name] = lines[index + 2].slice(prefix.length);
      });
      return { type: type, fields: fields };
    }

    function verifyEvent(event) {
      var sig = b64decode(event.signature || '');
      var signer = b64decode(event.signer_public || '');
      if (!sig || !signer) return null;
      if (!nacl.sign.detached.verify(utf8(event.body), sig, signer)) return null;
      try {
        var parsed = parse(event.body);
      } catch (error) {
        return null;
      }
      return { type: parsed.type, fields: parsed.fields, body: event.body, signer: signer };
    }

    function mul(a, b) {
      var p = 0;
      a &= 255;
      b &= 255;
      for (var i = 0; i < 8; i++) {
        if ((b & 1) === 1) p ^= a;
        var hi = a & 0x80;
        a = (a << 1) & 255;
        if (hi !== 0) a ^= 0x1b;
        b >>= 1;
      }
      return p;
    }

    function inv(a) {
      if (a === 0) throw new Error('A share is malformed.');
      var result = 1;
      var base = a;
      var exp = 254;
      while (exp > 0) {
        if ((exp & 1) === 1) result = mul(result, base);
        base = mul(base, base);
        exp >>= 1;
      }
      return result;
    }

    function evalPoly(coeff, x) {
      var y = 0;
      for (var i = coeff.length - 1; i >= 0; i--) y = mul(y, x) ^ coeff[i];
      return y;
    }

    function atZero(points) {
      var result = 0;
      for (var i = 0; i < points.length; i++) {
        var num = 1;
        var den = 1;
        for (var j = 0; j < points.length; j++) {
          if (i === j) continue;
          num = mul(num, points[j][0]);
          den = mul(den, points[i][0] ^ points[j][0]);
        }
        result ^= mul(points[i][1], mul(num, inv(den)));
      }
      return result;
    }

    function split(secret, k, n) {
      if (secret.length !== 32 || k < 1 || n < k || n > 15) throw new Error('Share threshold is not acceptable.');
      var ys = [];
      for (var index = 1; index <= n; index++) ys[index] = [];
      for (var byte = 0; byte < 32; byte++) {
        var coeff = [secret[byte]];
        for (var c = 1; c < k; c++) coeff[c] = nacl.randomBytes(1)[0];
        if (k > 1) {
          while (coeff[k - 1] === 0) coeff[k - 1] = nacl.randomBytes(1)[0];
        }
        for (var x = 1; x <= n; x++) ys[x].push(evalPoly(coeff, x));
      }
      var shares = [];
      for (var s = 1; s <= n; s++) {
        var blob = new Uint8Array(36);
        blob[0] = 1;
        blob[1] = s;
        blob[2] = k;
        blob[3] = n;
        for (var y = 0; y < 32; y++) blob[4 + y] = ys[s][y];
        shares.push(blob);
      }
      return shares;
    }

    function join(shares) {
      var points = {};
      var k = null;
      var count = 0;
      shares.forEach(function (share) {
        if (!share || share.length !== 36 || share[0] !== 1) throw new Error('A share is malformed.');
        if (k === null) k = share[2];
        if (share[2] !== k || points[share[1]]) throw new Error('Shares do not belong together.');
        points[share[1]] = share.slice(4);
        count++;
      });
      if (k === null || count < k) throw new Error('Not enough shares to reconstruct the key.');
      var indexes = Object.keys(points).map(function (item) { return parseInt(item, 10); }).sort(function (a, b) { return a - b; }).slice(0, k);
      var secret = new Uint8Array(32);
      for (var byte = 0; byte < 32; byte++) {
        var set = indexes.map(function (index) { return [index, points[index][byte]]; });
        secret[byte] = atZero(set);
      }
      return secret;
    }

    function encodeMessage(messageId, title, body) {
      var titleBytes = utf8(title);
      var bodyBytes = utf8(body);
      var out = new Uint8Array(6 + 32 + 4 + titleBytes.length + 4 + bodyBytes.length);
      utf8('LWMSG1').forEach(function (value, index) { out[index] = value; });
      utf8(messageId).forEach(function (value, index) { out[6 + index] = value; });
      var offset = 38;
      writeU32(out, offset, titleBytes.length);
      offset += 4;
      titleBytes.forEach(function (value, index) { out[offset + index] = value; });
      offset += titleBytes.length;
      writeU32(out, offset, bodyBytes.length);
      offset += 4;
      bodyBytes.forEach(function (value, index) { out[offset + index] = value; });
      return out;
    }

    function writeU32(out, offset, value) {
      out[offset] = (value >>> 24) & 255;
      out[offset + 1] = (value >>> 16) & 255;
      out[offset + 2] = (value >>> 8) & 255;
      out[offset + 3] = value & 255;
    }

    function readU32(bytes, offset) {
      return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
    }

    function decodeMessage(plain, expectedId) {
      if (plain.length < 46) return null;
      var magic = fromUtf8(plain.slice(0, 6));
      var id = fromUtf8(plain.slice(6, 38));
      if (magic !== 'LWMSG1' || id !== expectedId) return null;
      var titleLen = readU32(plain, 38);
      var offset = 42;
      if (titleLen > 200 || offset + titleLen + 4 > plain.length) return null;
      var title = fromUtf8(plain.slice(offset, offset + titleLen));
      offset += titleLen;
      var bodyLen = readU32(plain, offset);
      offset += 4;
      if (offset + bodyLen !== plain.length || bodyLen > 65536) return null;
      return { title: title, body: fromUtf8(plain.slice(offset)) };
    }

    function reduce(events, now) {
      var problems = [];
      var parsed = [];
      events.forEach(function (event) {
        var item = verifyEvent(event);
        if (!item) {
          problems.push('Ignored an event with a bad signature or shape.');
          return;
        }
        parsed.push(item);
      });
      var registers = {};
      parsed.forEach(function (item) {
        if (item.type === 'register') registers[item.body] = item;
      });
      var registerList = Object.keys(registers).map(function (key) { return registers[key]; });
      if (registerList.length !== 1) {
        return { status: 'invalid', problems: problems, currentRequestId: null };
      }
      var register = registerList[0];
      var recoveryRaw = b64decode(register.fields.recovery_pubkey);
      var trustedRaw = b64decode(register.fields.trusted_pubkey);
      if (!recoveryRaw || !same(register.signer, recoveryRaw)) {
        return { status: 'invalid', problems: problems, currentRequestId: null };
      }
      var history = { 0: trustedRaw };
      var recoveryEvents = {};
      var recoveryConflict = false;
      parsed.forEach(function (item) {
        if (['relock', 'rotate_trusted', 'rotate_recovery', 'revise'].indexOf(item.type) === -1) return;
        var seq = parseInt(item.fields.recovery_seq, 10);
        if (recoveryEvents[seq] && recoveryEvents[seq].body !== item.body) recoveryConflict = true;
        recoveryEvents[seq] = item;
      });
      if (recoveryConflict) return { status: 'conflict', problems: problems, currentRequestId: null };
      var expected = 1;
      var maxRelock = 0;
      var recoveryPubkey = register.fields.recovery_pubkey;
      var ciphertextSha256 = register.fields.ciphertext_sha256;
      var nonce = register.fields.nonce;
      var appliedRevises = {};
      while (recoveryEvents[expected]) {
        var record = recoveryEvents[expected];
        if (!same(record.signer, recoveryRaw)) break;
        if (record.type === 'relock') maxRelock = expected;
        if (record.type === 'rotate_trusted') trustedRaw = b64decode(record.fields.trusted_pubkey);
        if (record.type === 'rotate_recovery') {
          recoveryRaw = b64decode(record.fields.new_recovery_pubkey);
          recoveryPubkey = record.fields.new_recovery_pubkey;
        }
        if (record.type === 'revise') {
          ciphertextSha256 = record.fields.ciphertext_sha256;
          nonce = record.fields.nonce;
          appliedRevises[expected] = record;
        }
        history[expected] = trustedRaw;
        expected++;
      }
      var recoverySeq = expected - 1;
      var unlocks = {};
      var seqConflict = false;
      parsed.forEach(function (item) {
        if (item.type !== 'unlock_request') return;
        var seq = parseInt(item.fields.trusted_seq, 10);
        var seen = parseInt(item.fields.seen_recovery_seq, 10);
        var deadline = parseInt(item.fields.deadline, 10);
        var requested = parseInt(item.fields.requested_at, 10);
        if (seq < 1 || seen > recoverySeq || deadline !== requested + UNLOCK_WINDOW) return;
        if (!history[seen] || !same(item.signer, history[seen])) return;
        if (unlocks[seq] && unlocks[seq].body !== item.body) {
          var seenA = parseInt(unlocks[seq].fields.seen_recovery_seq, 10);
          if (seenA >= maxRelock || seen >= maxRelock) seqConflict = true;
          return;
        }
        unlocks[seq] = item;
      });
      var admissible = {};
      var nextTrusted = 1;
      while (unlocks[nextTrusted]) {
        admissible[nextTrusted] = unlocks[nextTrusted];
        nextTrusted++;
      }
      var cancelled = {};
      parsed.forEach(function (item) {
        if (item.type !== 'cancel') return;
        var unlock = null;
        Object.keys(admissible).forEach(function (key) {
          if (admissible[key].fields.request_id === item.fields.request_id) unlock = admissible[key];
        });
        if (!unlock) return;
        var cancelKey = b64decode(unlock.fields.cancel_pubkey);
        if (cancelKey && same(item.signer, cancelKey)) cancelled[item.fields.request_id] = true;
      });
      function seal(status, requestId, deadline) {
        var out = {
          status: status,
          problems: problems,
          currentRequestId: requestId || null,
          recoverySeq: recoverySeq,
          nextRecoverySeq: expected,
          nextTrustedSeq: nextTrusted,
          maxRelockSeq: maxRelock,
          ciphertextSha256: ciphertextSha256,
          nonce: nonce
        };
        if (deadline) out.deadline = deadline;
        if (status === 'published') out.k = parseInt(register.fields.k, 10);
        return out;
      }
      function voidedByRevise(unlock) {
        var seen = parseInt(unlock.fields.seen_recovery_seq, 10);
        var deadline = parseInt(unlock.fields.deadline, 10);
        var seqs = Object.keys(appliedRevises);
        for (var i = 0; i < seqs.length; i++) {
          var seq = parseInt(seqs[i], 10);
          if (seq <= seen) continue;
          if (parseInt(appliedRevises[seq].fields.revised_at, 10) < deadline) return true;
        }
        return false;
      }
      if (seqConflict) return seal('conflict', null, null);
      var current = null;
      Object.keys(admissible).map(function (key) { return parseInt(key, 10); }).sort(function (a, b) { return a - b; }).forEach(function (seq) {
        var seen = parseInt(admissible[seq].fields.seen_recovery_seq, 10);
        if (seen >= maxRelock && !voidedByRevise(admissible[seq])) current = admissible[seq].fields;
      });
      if (!current) return seal(maxRelock > 0 ? 'relocked' : 'locked', null, null);
      if (cancelled[current.request_id]) return seal('locked', current.request_id, null);
      if (now < parseInt(current.deadline, 10)) return seal('pending', current.request_id, current.deadline);
      return seal('published', current.request_id, current.deadline);
    }

    function verifyDirectory(document, pinned) {
      var body = document.directory || '';
      var sig = b64decode(document.signature || '');
      var signer = b64decode(document.signer_public || '');
      if (!sig || !signer || !nacl.sign.detached.verify(utf8(body), sig, signer)) return null;
      var lines = body.slice(0, -1).split('\n');
      if (lines[0] !== 'lastwords.directory.v1') return null;
      var fields = {};
      lines.slice(1).forEach(function (line) {
        var cut = line.indexOf('=');
        fields[line.slice(0, cut)] = line.slice(cut + 1);
      });
      var announced = b64decode(fields.sign_pubkey || '');
      if (!announced || !same(signer, announced)) return null;
      if (pinned && !acceptsPinnedKey(pinned, fields.sign_pubkey, document.rotations || [])) return null;
      return fields;
    }

    function acceptsPinnedKey(pinned, current, rotations) {
      var pinnedRaw = b64decode(pinned);
      var currentRaw = b64decode(current);
      if (!pinnedRaw || !currentRaw) return false;
      if (same(pinnedRaw, currentRaw)) return true;
      var cursor = pinned;
      var remaining = rotations.slice();
      for (var step = 0; step < 20; step++) {
        var cursorRaw = b64decode(cursor);
        if (cursorRaw && same(cursorRaw, currentRaw)) return true;
        var advanced = false;
        for (var i = 0; i < remaining.length; i++) {
          var rotation = remaining[i];
          if (!rotation) continue;
          var text = rotation.body || '';
          if (!text.endsWith('\n')) continue;
          var parts = text.slice(0, -1).split('\n');
          if (parts[0] !== 'lastwords.rotation.v1') continue;
          var map = {};
          parts.slice(1).forEach(function (line) {
            var cut = line.indexOf('=');
            map[line.slice(0, cut)] = line.slice(cut + 1);
          });
          var sig = b64decode(rotation.signature || '');
          var signer = b64decode(rotation.signer_public || '');
          var oldKey = b64decode(map.old_sign_pubkey || '');
          if (!sig || !signer || !oldKey) continue;
          if (!same(signer, oldKey) || !same(b64decode(cursor), oldKey)) continue;
          if (!nacl.sign.detached.verify(utf8(text), sig, signer)) continue;
          cursor = map.new_sign_pubkey;
          remaining.splice(i, 1);
          advanced = true;
          break;
        }
        if (!advanced) return false;
      }
      return false;
    }

    return {
      UNLOCK_WINDOW: UNLOCK_WINDOW,
      b64encode: b64encode,
      b64decode: b64decode,
      utf8: utf8,
      fromUtf8: fromUtf8,
      build: build,
      parse: parse,
      split: split,
      join: join,
      encodeMessage: encodeMessage,
      decodeMessage: decodeMessage,
      reduce: reduce,
      verifyDirectory: verifyDirectory,
      acceptsPinnedKey: acceptsPinnedKey,
      publicFromSecret: function (secret) { return secret.slice(32); }
    };
  }

  return { create: create };
});
