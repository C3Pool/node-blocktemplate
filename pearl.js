// Pearl (PRL) block template construction.
//
// Pearl is a btcd fork whose proof-of-work is a Plonky2 zk certificate over a
// NoisyGEMM matrix multiplication rather than a header hash. Two consequences
// drive everything in this file:
//
//   1. The block header is 108 bytes and has NO nonce. The 4-byte nonce field a
//      Bitcoin header carries is replaced by a 32-byte ProofCommitment appended
//      after nBits:
//
//        version(4) | prevBlock(32) | merkleRoot(32) | time(4) | bits(4) | proofCommitment(32)
//
//      (node/wire/blockheader.go: MaxBlockHeaderPayload = 12 + 32*3 = 108.)
//      The first 76 bytes -- everything up to and including nBits -- are the
//      "incomplete header" handed to miners; they return a certificate, and the
//      pool derives proofCommitment from it to complete the header.
//
//   2. A serialized block puts the CERTIFICATE FIRST, before the header
//      (node/wire/msgblock.go PrlEncode):
//
//        certificate | header(108) | varint(txCount) | transactions
//
//      So the template blob built here holds only "header || txCount || txs";
//      constructNewPearlBlob prepends the certificate at submit time.
//
// Everything else -- coinbase layout, BIP34 height, segwit witness commitment,
// merkle roots -- follows Bitcoin, so this file mirrors rtm.js closely.

const { BASE_PEARL_DIFF, difficultyToFloat } = require('./bigint');
const { taprootAddressToScript } = require('./bitcoin_utils');

const diff1 = BASE_PEARL_DIFF;

// node/wire/blockheader.go
const PEARL_HEADER_LEN = 108;
// Offset of proofCommitment inside the header; also the length of the
// "incomplete header" that miners receive.
const PEARL_INCOMPLETE_HEADER_LEN = 76;

// node/wire/certificate.go
const MAX_ZK_PROOF_SIZE = 60000;
const CERTIFICATE_MAX_SIZE = 65000;

// Certificate versions the consensus accepts (IsCertVersionAllowed).
const ALLOWED_CERT_VERSIONS = new Set([1, 2, 3]);

// node/wire/certificate_v1.go and certificate_v2.go. V1 (ZkDense) public data is
// a fixed 164 bytes; V2/V3 (ZkMoE) is variable and length-prefixed on the wire.
const PUBLIC_DATA_SIZE_V1 = 164;
const PUBLIC_DATA_MAX_SIZE_V2 = 4807;

// blockchain.WitnessMagicBytes -- the coinbase commitment output script is
// OP_RETURN OP_DATA_36 {0xaa21a9ed || commitment}. Note that Pearl's
// getblocktemplate returns default_witness_commitment as the BARE 32-byte
// commitment, not the full script Bitcoin Core hands out, so the prefix has to
// be added here.
const WITNESS_MAGIC_BYTES = Buffer.from('aa21a9ed', 'hex');
const WITNESS_COMMITMENT_SIZE = 32;

// The coinbase witness is a single 32-byte item (the witness reserved value).
// Keeping it all-zero is what makes the daemon's default_witness_commitment
// reusable: the coinbase wtxid is defined as zero, so the commitment does not
// depend on our scriptSig or extranonce.
const WITNESS_RESERVED_VALUE = Buffer.alloc(32, 0);

const EXTRA_NONCE_PLACEHOLDER_LENGTH = 17;
const MAX_PEARL_TEMPLATE_TRANSACTIONS = 4999;
const MAX_PEARL_TEMPLATE_TRANSACTION_BYTES = 64 * 1024 * 1024;

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

function isValidGrainAmount(amount) {
  return Number.isSafeInteger(amount) && amount >= 0;
}

// Amounts are in grain (1 PRL = 1e8 grain), same 64-bit LE encoding as satoshis.
function packInt64LE(num) {
  if (!isValidGrainAmount(num)) throw new Error('Invalid PRL transaction amount');
  const buff = Buffer.alloc(8);
  buff.writeUInt32LE(num % Math.pow(2, 32), 0);
  buff.writeUInt32LE(Math.floor(num / Math.pow(2, 32)), 4);
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
  const buff = Buffer.alloc(9);
  buff[0] = 0xff;
  buff.writeBigUInt64LE(BigInt(n), 1);
  return buff;
}

// Minimal script number encoding, used for the BIP34 height push.
function serializeNumber(n) {
  if (n >= 1 && n <= 16) return Buffer.from([0x50 + n]);
  let value = n;
  const buff = Buffer.alloc(9);
  let len = 1;
  while (value > 127) {
    buff.writeUInt8(value & 0xff, len++);
    value >>= 8;
  }
  buff.writeUInt8(len, 0);
  buff.writeUInt8(value, len++);
  return buff.slice(0, len);
}

function serializeString(s) {
  const data = Buffer.from(s, 'utf8');
  return Buffer.concat([varIntBuffer(data.length), data]);
}

function witnessCommitmentScript(commitmentHex) {
  const commitment = Buffer.from(commitmentHex, 'hex');
  if (commitment.length !== WITNESS_COMMITMENT_SIZE) {
    throw new Error('Invalid PRL default_witness_commitment');
  }
  const payload = Buffer.concat([WITNESS_MAGIC_BYTES, commitment]);
  // OP_RETURN OP_DATA_36 <payload>
  return Buffer.concat([Buffer.from([0x6a, payload.length]), payload]);
}

function generateCoinbaseOutputs(rpcData, poolAddress) {
  const outputs = [];

  // Pearl consensus only permits P2TR / P2MR / OP_RETURN coinbase outputs
  // (node/blockchain/validate.go). The pool pays itself to a Taproot address.
  const payScript = taprootAddressToScript(poolAddress, 'prl');
  if (!isValidGrainAmount(rpcData.coinbasevalue)) throw new Error('Invalid PRL coinbasevalue');
  outputs.push(Buffer.concat([
    packInt64LE(rpcData.coinbasevalue),
    varIntBuffer(payScript.length),
    payScript
  ]));

  if (rpcData.default_witness_commitment !== undefined) {
    const script = witnessCommitmentScript(rpcData.default_witness_commitment);
    outputs.push(Buffer.concat([
      packInt64LE(0),
      varIntBuffer(script.length),
      script
    ]));
  }

  return Buffer.concat([varIntBuffer(outputs.length), Buffer.concat(outputs)]);
}

function decodePearlTransactionData(tx) {
  if (!tx || typeof tx.data !== 'string') throw new Error('Missing PRL transaction data');
  const buffer = Buffer.from(tx.data, 'hex');
  if (buffer.length === 0 || buffer.toString('hex') !== tx.data.toLowerCase()) {
    throw new Error('Malformed PRL transaction hex');
  }
  return buffer;
}

function describePearlTransaction(tx) {
  if (!tx) return 'unknown';
  return String(tx.txid || tx.hash || 'unknown');
}

// Builds a Pearl block template.
//
// Returns the same shape as RtmBlockTemplate so the pool's generic BTC-style
// paths keep working, except that blocktemplate_blob starts with a 108-byte
// header instead of an 80-byte one and carries no nonce field:
//
//   blocktemplate_blob = header(108, merkleRoot and proofCommitment zeroed)
//                        || varint(txCount) || coinbase || transactions
//   reserved_offset    = start of the extranonce placeholder inside the coinbase
module.exports.PearlBlockTemplate = function (rpcData, poolAddress) {
  if (!rpcData || typeof rpcData !== 'object') throw new Error('Invalid PRL template');

  const scriptSigPart1 = Buffer.concat([
    // BIP34 height, required by consensus.
    serializeNumber(rpcData.height),
    serializeNumber(Math.floor(Date.now() / 1000)),
    Buffer.from([EXTRA_NONCE_PLACEHOLDER_LENGTH])
  ]);
  const scriptSigPart2 = serializeString('/nodeStratum/');

  const isWitness = rpcData.default_witness_commitment !== undefined;

  const blob1 = Buffer.concat([
    packUInt32LE(1), // coinbase tx version
    Buffer.from(isWitness ? '0001' : '', 'hex'), // segwit marker/flag
    varIntBuffer(1), // input count
    Buffer.alloc(32, 0), // null prevout hash
    packUInt32LE(0xffffffff), // null prevout index
    varIntBuffer(scriptSigPart1.length + EXTRA_NONCE_PLACEHOLDER_LENGTH + scriptSigPart2.length),
    scriptSigPart1
  ]);

  const blob2 = Buffer.concat([
    scriptSigPart2,
    packUInt32LE(0), // input sequence
    generateCoinbaseOutputs(rpcData, poolAddress),
    isWitness
      ? Buffer.concat([
        varIntBuffer(1), // witness stack items
        varIntBuffer(WITNESS_RESERVED_VALUE.length),
        WITNESS_RESERVED_VALUE
      ])
      : Buffer.alloc(0),
    packUInt32LE(0) // lock time
  ]);

  const prevHashBuf = Buffer.from(rpcData.previousblockhash || '', 'hex');
  if (prevHashBuf.length !== 32) throw new Error('Invalid PRL previousblockhash');
  const prev_hash = reverseBuffer(prevHashBuf).toString('hex');

  if (!Number.isInteger(rpcData.version) || rpcData.version < -0x80000000 || rpcData.version > 0x7fffffff) {
    throw new Error('Invalid PRL version');
  }
  const version = packInt32LE(rpcData.version).toString('hex');
  const curtime = packUInt32LE(rpcData.curtime).toString('hex');

  // getblocktemplate reports nBits big-endian; the wire format is little-endian.
  const bits = Buffer.from(rpcData.bits, 'hex');
  if (bits.length !== 4) throw new Error('Invalid PRL bits');
  bits.writeUInt32LE(bits.readUInt32BE());

  if (!Array.isArray(rpcData.transactions)) throw new Error('Invalid PRL transactions');
  if (rpcData.transactions.length > MAX_PEARL_TEMPLATE_TRANSACTIONS) throw new Error('Too many PRL transactions');

  // Include every daemon-selected transaction: the merkle root must cover
  // exactly the daemon's set, so dropping one yields a self-consistent block
  // the daemon then rejects. Fail closed rather than mine a doomed block.
  const txs = [];
  let txBytes = 0;
  rpcData.transactions.forEach(function (tx) {
    let txBuffer;
    try {
      txBuffer = decodePearlTransactionData(tx);
    } catch (err) {
      throw new Error(`Unparseable PRL transaction (${describePearlTransaction(tx)}): ${err.message}`);
    }
    txBytes += txBuffer.length;
    if (txBytes > MAX_PEARL_TEMPLATE_TRANSACTION_BYTES) throw new Error('PRL transaction data is too large');
    txs.push(txBuffer);
  });

  const txn = varIntBuffer(txs.length + 1);

  const header =
    version +
    prev_hash +
    Buffer.alloc(32, 0).toString('hex') + // merkleRoot, filled in later
    curtime +
    bits.toString('hex') +
    Buffer.alloc(32, 0).toString('hex'); // proofCommitment, filled in at submit

  return {
    difficulty: difficultyToFloat(diff1, rpcData.target, 16, 'PRL target'),
    height: rpcData.height,
    // Which certificate circuit a block on this template must carry. The
    // consensus rule moves with height (params.go RequiredCertVersion), so it
    // has to travel with the template rather than be pinned here: a share is
    // opened under this version, and opening it under another one fails.
    cert_version: rpcData.requiredcertversion,
    prev_hash,
    blocktemplate_blob:
      header +
      txn.toString('hex') +
      blob1.toString('hex') +
      Buffer.alloc(EXTRA_NONCE_PLACEHOLDER_LENGTH, 0xCC).toString('hex') +
      blob2.toString('hex') +
      Buffer.concat(txs).toString('hex'),
    reserved_offset: PEARL_HEADER_LEN + txn.length + blob1.length
  };
};

// Serializes a ZK certificate exactly as MsgCertificate.PrlEncode does
// (node/wire/certificate.go: version first, then the version's own body):
//
//   V1: version(4 LE) | blockHash(32) | publicData(164)              | proofLen(4) | proof
//   V2: version(4 LE) | blockHash(32) | pubLen(4) | publicData(var)  | proofLen(4) | proof
//   V3: identical to V2 on the wire; only the ProofCommitment domain differs.
//
// blockHash is the INTERNAL (little-endian) hash of the completed 108-byte
// header, not the big-endian form explorers display.
function serializePearlCertificate(certVersion, blockHashBuff, publicDataBuff, proofBuff) {
  if (!ALLOWED_CERT_VERSIONS.has(certVersion)) {
    throw new Error(`Unsupported PRL certificate version: ${certVersion}`);
  }
  if (!Buffer.isBuffer(blockHashBuff) || blockHashBuff.length !== 32) throw new Error('Invalid PRL block hash');
  if (!Buffer.isBuffer(publicDataBuff) || publicDataBuff.length === 0) throw new Error('Invalid PRL public_data');
  if (certVersion === 1 && publicDataBuff.length !== PUBLIC_DATA_SIZE_V1) {
    throw new Error(`PRL V1 public_data is ${publicDataBuff.length} bytes, need ${PUBLIC_DATA_SIZE_V1}`);
  }
  if (certVersion !== 1 && publicDataBuff.length > PUBLIC_DATA_MAX_SIZE_V2) {
    throw new Error(`PRL public_data is ${publicDataBuff.length} bytes, max ${PUBLIC_DATA_MAX_SIZE_V2}`);
  }
  if (!Buffer.isBuffer(proofBuff) || proofBuff.length === 0 || proofBuff.length > MAX_ZK_PROOF_SIZE) {
    throw new Error('Invalid PRL proof size');
  }
  const parts = [packUInt32LE(certVersion), blockHashBuff];
  // V1's public_data is fixed length, so only V2/V3 prefix it with its size.
  if (certVersion !== 1) parts.push(packUInt32LE(publicDataBuff.length));
  parts.push(publicDataBuff, packUInt32LE(proofBuff.length), proofBuff);
  return Buffer.concat(parts);
}

// Length of the certificate that prefixes a serialized block, so the header
// after it can be found without re-deriving it from the certificate's parts.
function pearlCertificateLength(blockBuffer) {
  if (!Buffer.isBuffer(blockBuffer) || blockBuffer.length < 4 + 32 + 4) throw new Error('Truncated PRL block');
  const certVersion = blockBuffer.readUInt32LE(0);
  if (!ALLOWED_CERT_VERSIONS.has(certVersion)) {
    throw new Error(`Unsupported PRL certificate version: ${certVersion}`);
  }
  let offset = 4 + 32;
  let publicDataLen = PUBLIC_DATA_SIZE_V1;
  if (certVersion !== 1) {
    publicDataLen = blockBuffer.readUInt32LE(offset);
    offset += 4;
    if (publicDataLen > PUBLIC_DATA_MAX_SIZE_V2) throw new Error('Invalid PRL public_data length');
  }
  offset += publicDataLen;
  if (offset + 4 > blockBuffer.length) throw new Error('Truncated PRL certificate');
  const proofLen = blockBuffer.readUInt32LE(offset);
  if (proofLen > MAX_ZK_PROOF_SIZE) throw new Error('Invalid PRL proof length');
  offset += 4 + proofLen;
  if (offset + PEARL_HEADER_LEN > blockBuffer.length) throw new Error('Truncated PRL block');
  return offset;
}

module.exports.PEARL_HEADER_LEN = PEARL_HEADER_LEN;
module.exports.PEARL_INCOMPLETE_HEADER_LEN = PEARL_INCOMPLETE_HEADER_LEN;
module.exports.MAX_ZK_PROOF_SIZE = MAX_ZK_PROOF_SIZE;
module.exports.CERTIFICATE_MAX_SIZE = CERTIFICATE_MAX_SIZE;
module.exports.ALLOWED_CERT_VERSIONS = ALLOWED_CERT_VERSIONS;
module.exports.varIntBuffer = varIntBuffer;
module.exports.serializeNumber = serializeNumber;
module.exports.witnessCommitmentScript = witnessCommitmentScript;
module.exports.PUBLIC_DATA_SIZE_V1 = PUBLIC_DATA_SIZE_V1;
module.exports.PUBLIC_DATA_MAX_SIZE_V2 = PUBLIC_DATA_MAX_SIZE_V2;
module.exports.serializePearlCertificate = serializePearlCertificate;
module.exports.pearlCertificateLength = pearlCertificateLength;
