'use strict';

// Pearl helpers that live in index.js. Kept separate from pearl.test.js because
// index.js loads the native addon, so these only run where it has been built.
//
// This is the highest-risk code in the Pearl path: a single wrong byte in the
// merkle root or the certificate-first assembly produces a block the daemon
// silently rejects, which on a live pool looks like nothing worse than bad luck.

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const blockTemplate = require('../index.js');
const pearl = require('../pearl.js');

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'pearl-gbt-mainnet.json'), 'utf8')
);
const POOL_ADDRESS = 'prl1p640xfps6m9uj6f8k7r7hlsaqph0ent8yta9ve9hh7enk7snrnp9s2lv4d0';

const HEADER_LEN = 108;
const INCOMPLETE_HEADER_LEN = 76;

function sha256(b) { return crypto.createHash('sha256').update(b).digest(); }
function hash256(b) { return sha256(sha256(b)); }

function buildBlob() {
  const tpl = blockTemplate.PearlBlockTemplate(FIXTURE, POOL_ADDRESS);
  return { tpl, blob: Buffer.from(tpl.blocktemplate_blob, 'hex') };
}

// Independent merkle computation: coinbase txid is hashed from its
// witness-stripped serialization, the rest come straight from the daemon.
function expectedMerkleRoot(blob, tpl) {
  const coinbaseStart = HEADER_LEN + 1; // 26 txs -> single-byte varint
  let coinbaseEnd = blob.length;
  for (const tx of FIXTURE.transactions) {
    const buf = Buffer.from(tx.data, 'hex');
    const idx = blob.indexOf(buf, coinbaseStart);
    if (idx >= 0 && idx < coinbaseEnd) coinbaseEnd = idx;
  }
  const coinbaseWithWitness = blob.slice(coinbaseStart, coinbaseEnd);

  // Strip the segwit marker/flag and the witness stack to get the txid preimage.
  const version = coinbaseWithWitness.slice(0, 4);
  assert.strictEqual(coinbaseWithWitness[4], 0x00);
  assert.strictEqual(coinbaseWithWitness[5], 0x01);
  const body = coinbaseWithWitness.slice(6);
  // witness = varint(1) varint(32) <32 zero bytes>, immediately before locktime
  const witnessLen = 1 + 1 + 32;
  const locktime = body.slice(body.length - 4);
  const bodyNoWitness = body.slice(0, body.length - 4 - witnessLen);
  const coinbaseTxid = hash256(Buffer.concat([version, bodyNoWitness, locktime]));

  let level = [coinbaseTxid].concat(
    FIXTURE.transactions.map((tx) => Buffer.from(tx.txid, 'hex').reverse())
  );
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(hash256(Buffer.concat([left, right])));
    }
    level = next;
  }
  assert.ok(tpl);
  return level[0];
}

test('convertPearlBlob returns the 76-byte incomplete header with a real merkle root', () => {
  const { tpl, blob } = buildBlob();
  const incomplete = blockTemplate.convertPearlBlob(blob);

  assert.strictEqual(incomplete.length, INCOMPLETE_HEADER_LEN);
  const merkle = incomplete.slice(36, 68);
  assert.notStrictEqual(merkle.toString('hex'), '00'.repeat(32), 'merkle root must be filled in');

  // Cross-check against an independently computed root: if these disagree the
  // daemon would reject every block we ever find.
  assert.strictEqual(merkle.toString('hex'), expectedMerkleRoot(blob, tpl).toString('hex'));

  // The fields ahead of the merkle root must be untouched.
  assert.strictEqual(incomplete.readInt32LE(0), FIXTURE.version);
  assert.strictEqual(incomplete.readUInt32LE(68), FIXTURE.curtime);
});

test('pearlProofCommitment is SHA256d(certVersion_LE || publicData)', () => {
  const publicData = Buffer.from('0123456789abcdef'.repeat(8), 'hex');
  for (const version of [1, 2, 3]) {
    const versionBuff = Buffer.alloc(4);
    versionBuff.writeUInt32LE(version, 0);
    const expected = hash256(Buffer.concat([versionBuff, publicData]));
    assert.strictEqual(
      blockTemplate.pearlProofCommitment(version, publicData).toString('hex'),
      expected.toString('hex')
    );
  }
});

test('pearlProofCommitment rejects certificate versions consensus does not allow', () => {
  const publicData = Buffer.alloc(16, 7);
  assert.throws(() => blockTemplate.pearlProofCommitment(0, publicData), /certificate version/);
  assert.throws(() => blockTemplate.pearlProofCommitment(4, publicData), /certificate version/);
});

test('constructNewPearlBlob puts the certificate before the header', () => {
  const { blob } = buildBlob();
  const publicData = Buffer.alloc(164, 0xAB);
  const proof = Buffer.alloc(512, 0x5A);

  const block = blockTemplate.constructNewPearlBlob(Buffer.from(blob), 3, publicData, proof);

  // certificate || header(108) || varint(txCount) || transactions
  const certLen = pearl.pearlCertificateLength(block);
  const cert = block.slice(0, certLen);
  assert.strictEqual(block.length, certLen + blob.length, 'the template body must be carried through intact');
  assert.strictEqual(
    block.slice(certLen + HEADER_LEN).toString('hex'),
    blob.slice(HEADER_LEN).toString('hex'),
    'nothing after the header may change'
  );

  const header = block.slice(certLen, certLen + HEADER_LEN);
  const versionBuff = Buffer.alloc(4);
  versionBuff.writeUInt32LE(3, 0);
  assert.strictEqual(
    header.slice(INCOMPLETE_HEADER_LEN).toString('hex'),
    hash256(Buffer.concat([versionBuff, publicData])).toString('hex'),
    'the last 32 header bytes are the proof commitment over the public data'
  );
  assert.notStrictEqual(header.slice(36, 68).toString('hex'), '00'.repeat(32), 'merkle must be filled');

  // The certificate carries the hash of the very header those 32 bytes
  // completed -- the one ordering mistake that would still assemble cleanly.
  assert.strictEqual(
    cert.slice(4, 36).toString('hex'),
    hash256(header).toString('hex'),
    'certificate must carry the completed header hash'
  );
  assert.strictEqual(
    cert.toString('hex'),
    pearl.serializePearlCertificate(3, hash256(header), publicData, proof).toString('hex')
  );
});

test('constructNewPearlBlob refuses malformed inputs', () => {
  const { blob } = buildBlob();
  assert.throws(
    () => blockTemplate.constructNewPearlBlob(Buffer.from(blob), 0, Buffer.alloc(164), Buffer.alloc(32)),
    /certificate version/
  );
  assert.throws(
    () => blockTemplate.constructNewPearlBlob(Buffer.from(blob), 1, Buffer.alloc(163), Buffer.alloc(32)),
    /public_data/
  );
  assert.throws(
    () => blockTemplate.constructNewPearlBlob(
      Buffer.from(blob),
      3,
      Buffer.alloc(164),
      Buffer.alloc(pearl.MAX_ZK_PROOF_SIZE + 1)
    ),
    /proof size/
  );
  // The 'certificate too large' guard in index.js has no test because it cannot
  // be reached: the field caps above bound a certificate at 4+32+4+4807+4+60000
  // = 64851 bytes, under CertificateMaxSize. It stays as a backstop in case the
  // node ever raises one of those caps without raising the total.
  assert.ok(4 + 32 + 4 + pearl.PUBLIC_DATA_MAX_SIZE_V2 + 4 + pearl.MAX_ZK_PROOF_SIZE < pearl.CERTIFICATE_MAX_SIZE);
});

test('pearlBlockHashBuff hashes exactly the 108-byte header', () => {
  const { blob } = buildBlob();
  const block = blockTemplate.constructNewPearlBlob(Buffer.from(blob), 3, Buffer.alloc(164, 2), Buffer.alloc(32, 1));
  const header = block.slice(pearl.pearlCertificateLength(block), pearl.pearlCertificateLength(block) + HEADER_LEN);

  const hash = blockTemplate.pearlBlockHashBuff(header);
  assert.strictEqual(hash.length, 32);
  assert.strictEqual(hash.toString('hex'), Buffer.from(hash256(header)).reverse().toString('hex'));

  assert.throws(() => blockTemplate.pearlBlockHashBuff(header.slice(0, 80)), /header length/);
});

test('getPearlBlockId walks past the certificate to find the header', () => {
  const { blob } = buildBlob();
  const block = blockTemplate.constructNewPearlBlob(Buffer.from(blob), 3, Buffer.alloc(164, 9), Buffer.alloc(700, 3));
  const header = block.slice(pearl.pearlCertificateLength(block), pearl.pearlCertificateLength(block) + HEADER_LEN);

  assert.strictEqual(
    blockTemplate.getPearlBlockId(block).toString('hex'),
    blockTemplate.pearlBlockHashBuff(header).toString('hex')
  );
});
