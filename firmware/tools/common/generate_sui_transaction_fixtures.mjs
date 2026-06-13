#!/usr/bin/env node

import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TransactionDataBuilder } from '@mysten/sui/transactions';

// Schema evidence: MystenLabs/sui TypeScript SDK commit
// af72024d8a88062e35a9499da7d95e424a0e3c85 and @mysten/sui 2.17.0.
// Relevant source: packages/sui/src/bcs/bcs.ts and Transaction builder output.
//
// This generator is self-contained. .WORK/sources/ts-sdks is evidence for the
// schema, not a tracked build or test dependency. To avoid testing only our own
// local encoder assumptions, the positive fixture must match the SDK oracle hex
// below before this script writes any fixture.

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '../../..');
const outDir = resolve(
  repoRoot,
  'firmware/src/common/agent_q/sui/testdata/sui_transaction_facts',
);

const sender = '0x' + 'aa'.repeat(32);
const recipient = '0x' + 'bb'.repeat(32);
const sponsoredGasOwner = '0x' + 'ee'.repeat(32);
const gasObjectId = '0x' + 'cc'.repeat(32);
const gasDigest = 'dd'.repeat(32);
const amount = 1_000_000n;
const gasPrice = 1_000n;
const gasBudget = 50_000_000n;
const gasVersion = 7n;
const sdkOracleValidSuiTransferTxHex =
  '000002000840420f00000000000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0202000101000001010300000000010100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc070000000000000020ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaae80300000000000080f0fa020000000000';

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

function u32(value) {
  return Uint8Array.of(value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, (value >> 24) & 0xff);
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

function bool(value) {
  return Uint8Array.of(value ? 1 : 0);
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

function stringBytes(value) {
  return byteVector(new TextEncoder().encode(value));
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

function argNestedResult(commandIndex, resultIndex) {
  return enumVariant(3, concat(u16(commandIndex), u16(resultIndex)));
}

function splitCoinsCommand() {
  return enumVariant(2, concat(argGasCoin(), vector([argInput(0)])));
}

function transferObjectsCommand() {
  return enumVariant(1, concat(vector([argNestedResult(0, 0)]), argInput(1)));
}

function resultReferenceTransferObjectsCommand() {
  return enumVariant(1, concat(vector([argResult(0)]), argInput(1)));
}

function mergeCoinsCommand() {
  return enumVariant(3, concat(argGasCoin(), vector([])));
}

function typeTagU64() {
  return enumVariant(2);
}

function typeTagStruct(address, moduleName, structName, typeArgs = []) {
  return enumVariant(
    7,
    concat(
      hexToBytes(address),
      stringBytes(moduleName),
      stringBytes(structName),
      vector(typeArgs),
    ),
  );
}

function moveCallCommand() {
  return enumVariant(
    0,
    concat(
      hexToBytes('0x' + '22'.repeat(32)),
      stringBytes('pay'),
      stringBytes('spend'),
      vector([typeTagU64()]),
      vector([argInput(0)]),
    ),
  );
}

function moveCallVectorTypeArgCommand() {
  return enumVariant(
    0,
    concat(
      hexToBytes('0x' + '22'.repeat(32)),
      stringBytes('pay'),
      stringBytes('spend_vec'),
      vector([enumVariant(6, typeTagStruct('0x' + '02'.padStart(64, '0'), 'sui', 'SUI'))]),
      vector([argInput(0)]),
    ),
  );
}

function publishCommand() {
  return enumVariant(
    4,
    concat(
      vector([byteVector(Uint8Array.from([1, 2, 3, 4]))]),
      vector([hexToBytes('0x' + '11'.repeat(32))]),
    ),
  );
}

function upgradeCommand() {
  return enumVariant(
    6,
    concat(
      vector([byteVector(Uint8Array.from([5, 6, 7, 8]))]),
      vector([hexToBytes('0x' + '33'.repeat(32))]),
      hexToBytes('0x' + '44'.repeat(32)),
      argInput(0),
    ),
  );
}

function makeMoveVecCommand() {
  return enumVariant(
    5,
    concat(
      optionSomeTypeTag(typeTagStruct('0x' + '02'.padStart(64, '0'), 'sui', 'SUI')),
      vector([argInput(0)]),
    ),
  );
}

function moveCallOutOfRangeInputCommand() {
  return enumVariant(
    0,
    concat(
      hexToBytes('0x' + '22'.repeat(32)),
      stringBytes('pay'),
      stringBytes('spend'),
      vector([typeTagU64()]),
      vector([argInput(9)]),
    ),
  );
}

function suiObjectRef() {
  return concat(hexToBytes(gasObjectId), u64(gasVersion), byteVector(hexToBytes(gasDigest)));
}

function gasData(owner = sender) {
  return concat(vector([suiObjectRef()]), hexToBytes(owner), u64(gasPrice), u64(gasBudget));
}

function programmableTransaction(commands) {
  return programmableTransactionWithInputs([
    pure(u64(amount)),
    pure(hexToBytes(recipient)),
  ], commands);
}

function programmableTransactionWithInputs(inputs, commands) {
  return enumVariant(
    0,
    concat(
      vector(inputs),
      vector(commands),
    ),
  );
}

function transactionData(commands, gasOwner = sender) {
  return transactionDataWithInputs([
    pure(u64(amount)),
    pure(hexToBytes(recipient)),
  ], commands, gasOwner);
}

function transactionDataWithInputs(inputs, commands, gasOwner = sender, expiration = enumVariant(0)) {
  return enumVariant(
    0,
    concat(programmableTransactionWithInputs(inputs, commands), hexToBytes(sender), gasData(gasOwner), expiration),
  );
}

function optionNone() {
  return enumVariant(0);
}

function optionSomeU64(value) {
  return enumVariant(1, u64(value));
}

function optionSomeTypeTag(value) {
  return enumVariant(1, value);
}

function validDuringExpiration() {
  return enumVariant(
    2,
    concat(
      optionSomeU64(10n),
      optionSomeU64(20n),
      optionNone(),
      optionSomeU64(123456789n),
      byteVector(hexToBytes('55'.repeat(32))),
      u32(42),
    ),
  );
}

function epochExpiration() {
  return enumVariant(1, u64(123n));
}

function objectImmOrOwnedInput() {
  return enumVariant(1, enumVariant(0, suiObjectRef()));
}

function sharedObjectInput() {
  return enumVariant(
    1,
    enumVariant(
      1,
      concat(
        hexToBytes('0x' + '66'.repeat(32)),
        u64(9n),
        bool(true),
      ),
    ),
  );
}

function receivingObjectInput() {
  return enumVariant(1, enumVariant(2, suiObjectRef()));
}

function unsupportedMergeCoinsTx() {
  return transactionData([mergeCoinsCommand()]);
}

function moveCallTx() {
  return enumVariant(
    0,
    concat(
      enumVariant(
        0,
        concat(
          vector([pure(u64(amount))]),
          vector([moveCallCommand()]),
        ),
      ),
      hexToBytes(sender),
      gasData(),
      enumVariant(0),
    ),
  );
}

function moveCallVectorTypeArgTx() {
  return transactionDataWithInputs([pure(u64(amount))], [moveCallVectorTypeArgCommand()]);
}

function publishTx() {
  return transactionDataWithInputs([], [publishCommand()]);
}

function upgradeTx() {
  return transactionDataWithInputs([pure(u64(amount))], [upgradeCommand()]);
}

function fundsWithdrawalInput(withdrawFromVariant = 0) {
  return enumVariant(
    2,
    concat(
      enumVariant(0, u64(amount)),
      enumVariant(0, typeTagStruct('0x' + '02'.padStart(64, '0'), 'sui', 'SUI')),
      enumVariant(withdrawFromVariant),
    ),
  );
}

function fundsWithdrawalTx() {
  return transactionDataWithInputs([fundsWithdrawalInput(0)], [moveCallCommand()]);
}

function validDuringTx() {
  return transactionDataWithInputs([], [publishCommand()], sender, validDuringExpiration());
}

function epochExpirationTx() {
  return transactionDataWithInputs([], [publishCommand()], sender, epochExpiration());
}

function makeMoveVecTx() {
  return transactionDataWithInputs([objectImmOrOwnedInput()], [makeMoveVecCommand()]);
}

function sharedObjectMoveCallTx() {
  return transactionDataWithInputs([sharedObjectInput()], [moveCallCommand()]);
}

function receivingObjectMakeMoveVecTx() {
  return transactionDataWithInputs([receivingObjectInput()], [makeMoveVecCommand()]);
}

function largePureInputTx() {
  return transactionDataWithInputs(
    [
      pure(Uint8Array.from({ length: 80 }, (_value, index) => index)),
      pure(hexToBytes(recipient)),
    ],
    [splitCoinsCommand(), transferObjectsCommand()],
  );
}

function moveCallOutOfRangeInputTx() {
  return enumVariant(
    0,
    concat(
      enumVariant(
        0,
        concat(
          vector([pure(u64(amount))]),
          vector([moveCallOutOfRangeInputCommand()]),
        ),
      ),
      hexToBytes(sender),
      gasData(),
      enumVariant(0),
    ),
  );
}

function transactionKindOnlyTransfer() {
  return programmableTransaction([splitCoinsCommand(), transferObjectsCommand()]);
}

function wrongCommandOrderTx() {
  return transactionData([transferObjectsCommand(), splitCoinsCommand()]);
}

function resultReferenceTransferTx() {
  return transactionData([splitCoinsCommand(), resultReferenceTransferObjectsCommand()]);
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

function stringifyJson(value) {
  return JSON.stringify(
    value,
    (_key, jsonValue) => (typeof jsonValue === 'bigint' ? jsonValue.toString() : jsonValue),
    2,
  );
}

function sdkV2Snapshot(bytes) {
  return TransactionDataBuilder.fromBytes(bytes).snapshot();
}

function sdkV2ComparableFacts(snapshot) {
  return {
    sender: snapshot.sender,
    gasOwner: snapshot.gasData.owner,
    gasBudget: snapshot.gasData.budget,
    gasPrice: snapshot.gasData.price,
    inputCount: snapshot.inputs.length,
    commandCount: snapshot.commands.length,
    firstCommandKind: snapshot.commands[0]?.$kind ?? null,
    expirationKind: snapshot.expiration?.$kind ?? null,
  };
}

async function writeSdkV2Oracle(baseName, bytes) {
  const snapshot = sdkV2Snapshot(bytes);
  await writeText(`${baseName}.sdk-v2.json`, stringifyJson(snapshot));
  await writeText(`${baseName}.sdk-v2-facts.json`, stringifyJson(sdkV2ComparableFacts(snapshot)));
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
  await writeSdkV2Oracle('valid_sui_transfer_tx', valid);
  await writeText(
    'valid_sui_transfer_facts.json',
    stringifyJson(
      {
        sender,
        gasOwner: sender,
        recipient,
        asset: '0x2::sui::SUI',
        amount: amount.toString(),
        gasBudget: gasBudget.toString(),
        gasPrice: gasPrice.toString(),
        commandCount: 2,
      },
    ),
  );

  await writeText('malformed_short_tx.bcs.hex', bytesToHex(valid.slice(0, 12)));
  await writeText('trailing_bytes_tx.bcs.hex', `${bytesToHex(valid)}00`);
  const unsupportedMergeCoins = unsupportedMergeCoinsTx();
  await writeText('unsupported_merge_coins_tx.bcs.hex', bytesToHex(unsupportedMergeCoins));
  await writeSdkV2Oracle('unsupported_merge_coins_tx', unsupportedMergeCoins);
  const moveCall = moveCallTx();
  await writeText('move_call_tx.bcs.hex', bytesToHex(moveCall));
  await writeSdkV2Oracle('move_call_tx', moveCall);
  const moveCallVectorTypeArg = moveCallVectorTypeArgTx();
  await writeText('move_call_vector_type_arg_tx.bcs.hex', bytesToHex(moveCallVectorTypeArg));
  await writeSdkV2Oracle('move_call_vector_type_arg_tx', moveCallVectorTypeArg);
  const publish = publishTx();
  await writeText('publish_tx.bcs.hex', bytesToHex(publish));
  await writeSdkV2Oracle('publish_tx', publish);
  const upgrade = upgradeTx();
  await writeText('upgrade_tx.bcs.hex', bytesToHex(upgrade));
  await writeSdkV2Oracle('upgrade_tx', upgrade);
  const fundsWithdrawal = fundsWithdrawalTx();
  await writeText('funds_withdrawal_tx.bcs.hex', bytesToHex(fundsWithdrawal));
  await writeSdkV2Oracle('funds_withdrawal_tx', fundsWithdrawal);
  const validDuring = validDuringTx();
  await writeText('valid_during_tx.bcs.hex', bytesToHex(validDuring));
  await writeSdkV2Oracle('valid_during_tx', validDuring);
  const epochExpiration = epochExpirationTx();
  await writeText('epoch_expiration_tx.bcs.hex', bytesToHex(epochExpiration));
  await writeSdkV2Oracle('epoch_expiration_tx', epochExpiration);
  const makeMoveVec = makeMoveVecTx();
  await writeText('make_move_vec_tx.bcs.hex', bytesToHex(makeMoveVec));
  await writeSdkV2Oracle('make_move_vec_tx', makeMoveVec);
  const sharedObjectMoveCall = sharedObjectMoveCallTx();
  await writeText('shared_object_move_call_tx.bcs.hex', bytesToHex(sharedObjectMoveCall));
  await writeSdkV2Oracle('shared_object_move_call_tx', sharedObjectMoveCall);
  const receivingObjectMakeMoveVec = receivingObjectMakeMoveVecTx();
  await writeText('receiving_object_make_move_vec_tx.bcs.hex', bytesToHex(receivingObjectMakeMoveVec));
  await writeSdkV2Oracle('receiving_object_make_move_vec_tx', receivingObjectMakeMoveVec);
  const largePureInput = largePureInputTx();
  await writeText('large_pure_input_tx.bcs.hex', bytesToHex(largePureInput));
  await writeSdkV2Oracle('large_pure_input_tx', largePureInput);
  await writeText('move_call_out_of_range_input_tx.bcs.hex', bytesToHex(moveCallOutOfRangeInputTx()));
  await writeText('transaction_kind_only_sui_transfer_tx.bcs.hex', bytesToHex(transactionKindOnlyTransfer()));
  const sponsoredGasOwnerTx = transactionData([splitCoinsCommand(), transferObjectsCommand()], sponsoredGasOwner);
  await writeText(
    'sponsored_gas_owner_tx.bcs.hex',
    bytesToHex(sponsoredGasOwnerTx),
  );
  await writeSdkV2Oracle('sponsored_gas_owner_tx', sponsoredGasOwnerTx);
  await writeText('result_reference_transfer_tx.bcs.hex', bytesToHex(resultReferenceTransferTx()));
  await writeText('wrong_command_order_tx.bcs.hex', bytesToHex(wrongCommandOrderTx()));
  await writeText('too_many_commands_tx.bcs.hex', bytesToHex(tooManyCommandsTx()));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
