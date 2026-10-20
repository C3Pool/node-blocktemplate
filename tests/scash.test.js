'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const bt = require('..');

const sha256d = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
// A P2WPKH address on the SCASH regtest (hrp rscash) and one on Bitcoin regtest.
const bech32 = require('bech32');
const RSCASH = bech32.bech32.encode('rscash', [0].concat(bech32.bech32.toWords(Buffer.alloc(20, 7))));
const BCRT = bech32.bech32.encode('bcrt', [0].concat(bech32.bech32.toWords(Buffer.alloc(20, 7))));

function gbt(overrides) {
  return Object.assign({
    version: 0x20000000,
    previousblockhash: '11'.repeat(32),
    curtime: 1792500000,
    bits: '207fffff',
    target: '7fffff0000000000000000000000000000000000000000000000000000000000',
    height: 150,
    coinbasevalue: 5000000000,
    rx_epoch_duration: 86400,
    default_witness_commitment: '6a24aa21a9ed' + 'e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9',
    transactions: []
  }, overrides);
}

test('SCASH template: 112-byte header, extranonce in the coinbase, seed from the epoch', () => {
  const t = bt.ScashBlockTemplate(gbt(), RSCASH);
  const blob = Buffer.from(t.blocktemplate_blob, 'hex');
  assert.equal(blob.readInt32LE(0), 0x20000000);
  assert.equal(blob.slice(4, 36).toString('hex'), '11'.repeat(32));
  assert.equal(blob.readUInt32LE(68), 1792500000);
  assert.equal(blob.slice(72, 76).toString('hex'), 'ffff7f20');
  assert.equal(blob.slice(76, 112).toString('hex'), '00'.repeat(36)); // nonce + hashRandomX
  assert.equal(blob.slice(t.reserved_offset, t.reserved_offset + 17).toString('hex'), 'cc'.repeat(17));
  assert.equal(t.seed_hash, sha256d(Buffer.from(`Scash/RandomX/Epoch/${Math.floor(1792500000 / 86400)}`)).toString('hex'));
  assert.equal(t.height, 150);
});

test('SCASH blob conversion fills the merkle root and keeps hashRandomX zeroed', () => {
  const t = bt.ScashBlockTemplate(gbt(), RSCASH);
  const blob = Buffer.from(t.blocktemplate_blob, 'hex');
  Buffer.alloc(17, 0x01).copy(blob, t.reserved_offset);
  const header = bt.convertScashBlob(blob);
  assert.equal(header.length, 112);
  assert.notEqual(header.slice(36, 68).toString('hex'), '00'.repeat(32));
  assert.equal(header.slice(80).toString('hex'), '00'.repeat(32));
  // A different extranonce moves the merkle root.
  Buffer.alloc(17, 0x02).copy(blob, t.reserved_offset);
  assert.notEqual(bt.convertScashBlob(blob).slice(36, 68).toString('hex'), header.slice(36, 68).toString('hex'));
});

test('SCASH block assembly writes the nonce and RandomX hash; the block hash covers both', () => {
  const t = bt.ScashBlockTemplate(gbt(), RSCASH);
  const blob = Buffer.from(t.blocktemplate_blob, 'hex');
  const rx = Buffer.alloc(32, 0xab);
  const block = bt.constructNewScashBlob(Buffer.from(blob), Buffer.from('deadbeef', 'hex'), rx);
  assert.equal(block.slice(76, 80).toString('hex'), 'deadbeef');
  assert.deepEqual(block.slice(80, 112), rx);
  assert.equal(bt.scashBlockHashBuff(block).toString('hex'), Buffer.from(sha256d(block.slice(0, 112))).reverse().toString('hex'));
  assert.throws(() => bt.constructNewScashBlob(Buffer.from(blob), Buffer.alloc(4), Buffer.alloc(31)), /RandomX hash/);
});

test('SCASH refuses another chain\'s payout address and a malformed witness commitment', () => {
  assert.throws(() => bt.ScashBlockTemplate(gbt(), BCRT), /prefix/);
  assert.throws(() => bt.ScashBlockTemplate(gbt({ default_witness_commitment: 'e2'.repeat(32) }), RSCASH), /witness_commitment/);
});
