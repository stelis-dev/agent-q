#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Schema evidence: MystenLabs/sui TypeScript SDK commit
// af72024d8a88062e35a9499da7d95e424a0e3c85 and @mysten/sui 2.17.0.
// Relevant source: packages/sui/src/bcs/bcs.ts and Transaction builder output.
//
// This generator is intentionally self-contained. .WORK/sources/ts-sdks is
// evidence for the schema, not a tracked build or test dependency. To avoid
// testing only our own local encoder assumptions, the positive fixture must
// match the SDK oracle hex below before this script writes any fixture.

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../../..');
const outDir = resolve(
  repoRoot,
  'firmware/src/common/agent_q/sui/testdata/sui_transaction_facts',
);

const sender = '0x' + 'aa'.repeat(32);
const recipient = '0x' + 'bb'.repeat(32);
const gasObjectId = '0x' + 'cc'.repeat(32);
const gasDigest = 'dd'.repeat(32);
const amount = 1_000_000n;
const gasPrice = 1_000n;
const gasBudget = 50_000_000n;
const gasVersion = 7n;
const sdkOracleValidSuiTransferTxHex =
  '000002000840420f00000000000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb020200010100000101020000010100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc070000000000000020ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae80300000000000080f0fa020000000000';

function concat(...chunks) {
  const length = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function u8(value) {
  return Uint8Array.of(value);
}

function u16(value) {
  return Uint8Array.of(value & 0xff, (value >> 8) & 0xff);
}

function u64(value) {
  const out = new Uint8Array(8);
  let remaining = BigInt(value);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function uleb(value) {
  const bytes = [];
  let remaining = Number(value);
  do {
    let byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    if (remaining !== 0) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (remaining !== 0);
  return Uint8Array.from(bytes);
}

function vector(items) {
  return concat(uleb(items.length), ...items);
}

function byteVector(bytes) {
  return concat(uleb(bytes.length), bytes);
}

function hexToBytes(hex) {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error(`Invalid hex length: ${hex}`);
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function enumVariant(index, payload = new Uint8Array()) {
  return concat(uleb(index), payload);
}

function pure(bytes) {
  return enumVariant(0, byteVector(bytes));
}

function argGasCoin() {
  return enumVariant(0);
}

function argInput(index) {
  return enumVariant(1, u16(index));
}

function argResult(index) {
  return enumVariant(2, u16(index));
}

function splitCoinsCommand() {
  return enumVariant(2, concat(argGasCoin(), vector([argInput(0)])));
}

function transferObjectsCommand() {
  return enumVariant(1, concat(vector([argResult(0)]), argInput(1)));
}

function suiObjectRef() {
  return concat(hexToBytes(gasObjectId), u64(gasVersion), byteVector(hexToBytes(gasDigest)));
}

function gasData() {
  return concat(vector([suiObjectRef()]), hexToBytes(sender), u64(gasPrice), u64(gasBudget));
}

function programmableTransaction(commands) {
  return enumVariant(
    0,
    concat(
      vector([
        pure(u64(amount)),
        pure(hexToBytes(recipient)),
      ]),
      vector(commands),
    ),
  );
}

function transactionData(commands) {
  return enumVariant(0, concat(programmableTransaction(commands), hexToBytes(sender), gasData(), enumVariant(0)));
}

function unsupportedMergeCoinsTx() {
  return enumVariant(
    0,
    concat(
      enumVariant(
        0,
        concat(
          vector([pure(u64(amount)), pure(hexToBytes(recipient))]),
          vector([enumVariant(3), transferObjectsCommand()]),
        ),
      ),
      hexToBytes(sender),
      gasData(),
      enumVariant(0),
    ),
  );
}

function wrongCommandOrderTx() {
  return transactionData([transferObjectsCommand(), splitCoinsCommand()]);
}

function tooManyCommandsTx() {
  return enumVariant(
    0,
    concat(
      enumVariant(
        0,
        concat(
          vector([pure(u64(amount)), pure(hexToBytes(recipient))]),
          uleb(3),
        ),
      ),
      hexToBytes(sender),
      gasData(),
      enumVariant(0),
    ),
  );
}

async function writeText(name, text) {
  await writeFile(resolve(outDir, name), text.endsWith('\n') ? text : `${text}\n`, 'utf8');
}

async function main() {
  await mkdir(outDir, { recursive: true });

  const valid = transactionData([splitCoinsCommand(), transferObjectsCommand()]);
  const validHex = bytesToHex(valid);
  if (validHex !== sdkOracleValidSuiTransferTxHex) {
    throw new Error(
      [
        'Local Sui BCS encoder no longer matches the pinned SDK oracle.',
        `expected: ${sdkOracleValidSuiTransferTxHex}`,
        `actual:   ${validHex}`,
      ].join('\n'),
    );
  }
  await writeText('valid_sui_transfer_tx.bcs.hex', sdkOracleValidSuiTransferTxHex);
  await writeText(
    'valid_sui_transfer_facts.json',
    JSON.stringify(
      {
        sender,
        recipient,
        asset: '0x2::sui::SUI',
        amount: amount.toString(),
        gasBudget: gasBudget.toString(),
        gasPrice: gasPrice.toString(),
        commandCount: 2,
      },
      null,
      2,
    ),
  );

  await writeText('malformed_short_tx.bcs.hex', bytesToHex(valid.slice(0, 12)));
  await writeText('trailing_bytes_tx.bcs.hex', `${bytesToHex(valid)}00`);
  await writeText('unsupported_merge_coins_tx.bcs.hex', bytesToHex(unsupportedMergeCoinsTx()));
  await writeText('wrong_command_order_tx.bcs.hex', bytesToHex(wrongCommandOrderTx()));
  await writeText('too_many_commands_tx.bcs.hex', bytesToHex(tooManyCommandsTx()));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
