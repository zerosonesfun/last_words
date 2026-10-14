var fs = require('fs');
var nacl = require(process.argv[2]);
var LastWords = require(process.argv[3]);
var fixture = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));
var lw = LastWords.create(nacl);

function fail(message) {
  console.error(message);
  process.exit(1);
}

function b64(text) {
  var bytes = lw.b64decode(text);
  if (!bytes) fail('bad base64');
  return bytes;
}

fixture.cases.forEach(function (item) {
  var pub = b64(item.public);
  var secret = b64(item.secret);
  var sig = b64(item.signature);
  if (!nacl.sign.detached.verify(lw.utf8(item.body), sig, pub)) fail('php signature did not verify');
  var opened = nacl.secretbox.open(b64(item.ciphertext), b64(item.nonce), b64(item.key));
  if (!opened) fail('ciphertext did not open');
  var decoded = lw.decodeMessage(opened, item.message_id);
  if (!decoded || decoded.body !== item.plain || decoded.title !== item.title) fail('plaintext mismatch');
  var shares = item.shares.map(b64);
  var joined = lw.join(shares);
  if (!nacl.verify(joined, b64(item.key))) fail('shares did not rebuild the key');
  var state = lw.reduce(item.events, item.now);
  if (state.status !== item.expect) fail('state ' + state.status + ' wanted ' + item.expect);
});

var sample = fixture.sign_body;
var sampleSecret = b64(fixture.sign_secret);
var sampleSig = nacl.sign.detached(lw.utf8(sample), sampleSecret);
fs.writeFileSync(process.argv[5], JSON.stringify({
  ok: true,
  signature: lw.b64encode(sampleSig)
}));
