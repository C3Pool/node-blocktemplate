// Satoshi Cash (SCASH) block template construction.
//
// SCASH is a Bitcoin Core fork mined with RandomX (Argon2 salt "RandomX-Scash\x01").
// Its block header is the 80-byte Bitcoin header followed by the 32-byte RandomX
// hash of the header itself (src/primitives/block.h, g_isRandomX):
//
//   version(4) | prevBlock(32) | merkleRoot(32) | time(4) | bits(4) | nonce(4) | hashRandomX(32)
//
// A block is valid when commitment = blake2b-256(header with hashRandomX zeroed ||
// hashRandomX), read as a little-endian number, is not above the target, and the
// header carries the RandomX hash of that zeroed header (src/pow.cpp
// CheckProofOfWorkRandomX). The RandomX key rotates by time, not by height:
// SHA256d("Scash/RandomX/Epoch/<nTime / rx_epoch_duration>") (GetSeedHash).
//
// Everything else -- coinbase, BIP34 height, segwit witness commitment, merkle
// root -- is Bitcoin Core, so this file mirrors pearl.js.
const crypto = require('crypto');
const bech32 = require('bech32');
const { BASE_DIFF, difficultyToFloat } = require('./bigint');
const diff1 = BASE_DIFF;
const SCASH_HEADER_LEN = 112;
const SCASH_NONCE_OFFSET = 76;
const SCASH_RX_HASH_OFFSET = 80;
// chainparams.cpp bech32_hrp: main, testnet, regtest.
const SCASH_ADDRESS_PREFIXES = new Set(['scash', 'tscash', 'rscash']);
// Bitcoin Core hands out default_witness_commitment as the whole output script:
// OP_RETURN OP_DATA_36 0xaa21a9ed <32-byte commitment>.
const WITNESS_COMMITMENT_SCRIPT_PREFIX = '6a24aa21a9ed';
const WITNESS_COMMITMENT_SCRIPT_LEN = 38;
// The coinbase witness is a single all-zero 32-byte item (the witness reserved
// value): the coinbase wtxid is defined as zero, so the daemon's commitment does
// not depend on our scriptSig or extranonce.
const WITNESS_RESERVED_VALUE = Buffer.alloc(32, 0);
const EXTRA_NONCE_PLACEHOLDER_LENGTH = 17;
const MAX_SCASH_TEMPLATE_TRANSACTIONS = 4999;
const MAX_SCASH_TEMPLATE_TRANSACTION_BYTES = 64 * 1024 * 1024;

function sha256d(buffer) {
  return crypto.createHash('sha256').update(crypto.createHash('sha256').update(buffer).digest()).digest();
}

function reverseBuffer(buff) {
  const reversed = Buffer.alloc(buff.length);
  for (let i = buff.length - 1; i >= 0; i--) reversed[buff.length - i - 1] = buff[i];
  return reversed;
}

function packInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeInt32LE(num, 0);
  return buff;
}

function packUInt32LE(num) {
  const buff = Buffer.alloc(4);
  buff.writeUInt32LE(num, 0);
  return buff;
}

function isValidSatoshisAmount(amount) {
  return Number.isSafeInteger(amount) && amount >= 0;
}

function packInt64LE(num) {
  const buff = Buffer.alloc(8);
  buff.writeBigInt64LE(BigInt(num), 0);
  return buff;
}

function varIntBuffer(n) {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) {
    const buff = Buffer.alloc(3);
    buff[0] = 0xfd;
    buff.writeUInt16LE(n, 1);
    return buff;
  }
  if (n <= 0xffffffff) {
    const buff = Buffer.alloc(5);
    buff[0] = 0xfe;
    buff.writeUInt32LE(n, 1);
    return buff;
  }
  throw new Error('varint too large');
}

// Minimal CScriptNum push for BIP34 heights and the coinbase timestamp.
function serializeNumber(nArg) {
  let n = nArg;
  if (n >= 1 && n <= 16) return Buffer.from([0x50 + n]);
  let l = 1;
  const buff = Buffer.alloc(9);
  while (n > 0x7f) {
    buff.writeUInt8(n & 0xff, l++);
    n >>= 8;
  }
  buff.writeUInt8(l, 0);
  buff.writeUInt8(n, l++);
  return buff.slice(0, l);
}

function serializeString(s) {
  if (s.length < 253) return Buffer.concat([Buffer.from([s.length]), Buffer.from(s)]);
  throw new Error('string too long');
}

// P2WPKH / P2WSH payout to a bech32 (witness v0) SCASH address. The prefix is
// enforced: a coinbase paid to a well-formed address of another chain is silent
// and unrecoverable.
function scashAddressToScript(addr) {
  if (typeof addr !== 'string' || addr.length > 90) throw new Error('Invalid SCASH address');
  let decoded;
  try {
    decoded = bech32.bech32.decode(addr);
  } catch (_err) {
    throw new Error('Invalid SCASH address');
  }
  if (!SCASH_ADDRESS_PREFIXES.has(decoded.prefix)) throw new Error(`Invalid SCASH address prefix: ${decoded.prefix}`);
  if (decoded.words.length < 1 || decoded.words[0] !== 0) throw new Error('Invalid SCASH address: not witness version 0');
  const program = Buffer.from(bech32.bech32.fromWords(decoded.words.slice(1)));
  if (program.length !== 20 && program.length !== 32) throw new Error('Invalid SCASH address: bad witness program');
  return Buffer.concat([Buffer.from([0x00, program.length]), program]);
}

function witnessCommitmentScript(scriptHex) {
  if (typeof scriptHex !== 'string' || !scriptHex.toLowerCase().startsWith(WITNESS_COMMITMENT_SCRIPT_PREFIX)) {
    throw new Error('Invalid SCASH default_witness_commitment');
  }
  const script = Buffer.from(scriptHex, 'hex');
  if (script.length !== WITNESS_COMMITMENT_SCRIPT_LEN) throw new Error('Invalid SCASH default_witness_commitment');
  return script;
}

function generateCoinbaseOutputs(rpcData, poolAddress) {
  const outputs = [];
  const payScript = scashAddressToScript(poolAddress);
  if (!isValidSatoshisAmount(rpcData.coinbasevalue)) throw new Error('Invalid SCASH coinbasevalue');
  outputs.push(Buffer.concat([packInt64LE(rpcData.coinbasevalue), varIntBuffer(payScript.length), payScript]));
  if (rpcData.default_witness_commitment !== undefined) {
    const script = witnessCommitmentScript(rpcData.default_witness_commitment);
    outputs.push(Buffer.concat([packInt64LE(0), varIntBuffer(script.length), script]));
  }
  return Buffer.concat([varIntBuffer(outputs.length), Buffer.concat(outputs)]);
}

function decodeScashTransactionData(tx) {
  if (!tx || typeof tx.data !== 'string') throw new Error('Missing SCASH transaction data');
  const buffer = Buffer.from(tx.data, 'hex');
  if (buffer.length === 0 || buffer.toString('hex') !== tx.data.toLowerCase()) {
    throw new Error('Malformed SCASH transaction hex');
  }
  return buffer;
}

// RandomX key for a header time: SHA256d("Scash/RandomX/Epoch/<time / duration>").
function scashSeedHash(time, epochDuration) {
  if (!Number.isSafeInteger(time) || time < 0) throw new Error('Invalid SCASH time');
  if (!Number.isSafeInteger(epochDuration) || epochDuration <= 0) throw new Error('Invalid SCASH rx_epoch_duration');
  return sha256d(Buffer.from(`Scash/RandomX/Epoch/${Math.floor(time / epochDuration)}`));
}

// Builds a SCASH block template, in the same shape as RtmBlockTemplate:
//
//   blocktemplate_blob = header(112: merkleRoot, nonce and hashRandomX zeroed)
//                        || varint(txCount) || coinbase || transactions
//   reserved_offset    = start of the extranonce placeholder inside the coinbase
//   seed_hash          = the RandomX key for the template's time
module.exports.ScashBlockTemplate = function (rpcData, poolAddress) {
  if (!rpcData || typeof rpcData !== 'object') throw new Error('Invalid SCASH template');

  const scriptSigPart1 = Buffer.concat([
    serializeNumber(rpcData.height), // BIP34
    serializeNumber(Math.floor(Date.now() / 1000)),
    Buffer.from([EXTRA_NONCE_PLACEHOLDER_LENGTH])
  ]);
  const scriptSigPart2 = serializeString('/nodeStratum/');
  const isWitness = rpcData.default_witness_commitment !== undefined;

  const blob1 = Buffer.concat([
    packUInt32LE(1), // coinbase tx version
    Buffer.from(isWitness ? '0001' : '', 'hex'), // segwit marker/flag
    varIntBuffer(1),
    Buffer.alloc(32, 0),
    packUInt32LE(0xffffffff),
    varIntBuffer(scriptSigPart1.length + EXTRA_NONCE_PLACEHOLDER_LENGTH + scriptSigPart2.length),
    scriptSigPart1
  ]);
  const blob2 = Buffer.concat([
    scriptSigPart2,
    packUInt32LE(0), // input sequence
    generateCoinbaseOutputs(rpcData, poolAddress),
    isWitness ? Buffer.concat([varIntBuffer(1), varIntBuffer(WITNESS_RESERVED_VALUE.length), WITNESS_RESERVED_VALUE]) : Buffer.alloc(0),
    packUInt32LE(0) // lock time
  ]);

  const prevHashBuf = Buffer.from(rpcData.previousblockhash || '', 'hex');
  if (prevHashBuf.length !== 32) throw new Error('Invalid SCASH previousblockhash');
  const prev_hash = reverseBuffer(prevHashBuf).toString('hex');
  if (!Number.isInteger(rpcData.version) || rpcData.version < -0x80000000 || rpcData.version > 0x7fffffff) {
    throw new Error('Invalid SCASH version');
  }
  if (!Number.isSafeInteger(rpcData.curtime) || rpcData.curtime < 0 || rpcData.curtime > 0xffffffff) {
    throw new Error('Invalid SCASH curtime');
  }
  const bits = Buffer.from(rpcData.bits || '', 'hex');
  if (bits.length !== 4) throw new Error('Invalid SCASH bits');
  bits.writeUInt32LE(bits.readUInt32BE()); // GBT reports nBits big-endian

  if (!Array.isArray(rpcData.transactions)) throw new Error('Invalid SCASH transactions');
  if (rpcData.transactions.length > MAX_SCASH_TEMPLATE_TRANSACTIONS) throw new Error('Too many SCASH transactions');
  // Every daemon-selected transaction goes in: the merkle root must cover exactly
  // the daemon's set, so a dropped one only yields a block the daemon rejects.
  const txs = [];
  let txBytes = 0;
  rpcData.transactions.forEach(function (tx) {
    let txBuffer;
    try {
      txBuffer = decodeScashTransactionData(tx);
    } catch (err) {
      throw new Error(`Unparseable SCASH transaction (${tx && (tx.txid || tx.hash)}): ${err.message}`);
    }
    txBytes += txBuffer.length;
    if (txBytes > MAX_SCASH_TEMPLATE_TRANSACTION_BYTES) throw new Error('SCASH transaction data is too large');
    txs.push(txBuffer);
  });

  const txn = varIntBuffer(txs.length + 1);
  const header = Buffer.concat([
    packInt32LE(rpcData.version),
    Buffer.from(prev_hash, 'hex'),
    Buffer.alloc(32, 0), // merkleRoot, filled in per extranonce
    packUInt32LE(rpcData.curtime),
    bits,
    Buffer.alloc(4, 0), // nonce, the miner's
    Buffer.alloc(32, 0) // hashRandomX, filled in at submit
  ]);

  return {
    difficulty: difficultyToFloat(diff1, rpcData.target, 16, 'SCASH target'),
    height: rpcData.height,
    prev_hash,
    seed_hash: scashSeedHash(rpcData.curtime, rpcData.rx_epoch_duration).toString('hex'),
    blocktemplate_blob:
      header.toString('hex') +
      txn.toString('hex') +
      blob1.toString('hex') +
      Buffer.alloc(EXTRA_NONCE_PLACEHOLDER_LENGTH, 0xCC).toString('hex') +
      blob2.toString('hex') +
      Buffer.concat(txs).toString('hex'),
    reserved_offset: SCASH_HEADER_LEN + txn.length + blob1.length
  };
};

module.exports.SCASH_HEADER_LEN = SCASH_HEADER_LEN;
module.exports.SCASH_NONCE_OFFSET = SCASH_NONCE_OFFSET;
module.exports.SCASH_RX_HASH_OFFSET = SCASH_RX_HASH_OFFSET;
module.exports.scashSeedHash = scashSeedHash;
module.exports.scashAddressToScript = scashAddressToScript;
module.exports.sha256d = sha256d;
