use aiken/builtin
use aiken/dict.{Dict, get, new}
use aiken/hash.{Blake2b_224, Blake2b_256, Hash}
use aiken/list
use aiken/transaction.{
  DatumHash, InlineDatum, Input, Output, OutputReference, ScriptContext, Spend,
  Transaction, TransactionId, find_input,
}
use aiken/transaction/credential.{Address, ScriptCredential, VerificationKey}
use aiken/transaction/value.{
  AssetName, PolicyId, Value, from_asset, from_lovelace, quantity_of,
}

type POSIXTime =
  Int

type Comments =
  List<ByteArray>

type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

type Owners =
  List<VerificationKeyHash>

type Photos =
  List<ByteArray>

type Datum {
  manufacturer: VerificationKeyHash,
  manufactuerdate: POSIXTime,
  expirydate: POSIXTime,
  photos: Photos,
  currentowner: VerificationKeyHash,
  owners: Owners,
  comments: Comments,
}

type Action {
  Comment
  Transfer
}

validator(policy_id: PolicyId, asset_name: AssetName) {
  fn supplychain(dtm: Datum, rdm: Action, ctx: ScriptContext) -> Bool {
    when rdm is {
      Comment ->
        must_be_signed_by(ctx.transaction, dtm.currentowner) && input_has_token(
          ctx,
          policy_id,
          asset_name,
        ) && output_has_token(ctx, policy_id, asset_name) && check_datum_for_comment(
          dtm,
          ctx,
        )
      Transfer ->
        must_be_signed_by(ctx.transaction, dtm.currentowner) && input_has_token(
          ctx,
          policy_id,
          asset_name,
        ) && output_has_token(ctx, policy_id, asset_name) && check_datum_for_transfer(
          dtm,
          ctx,
        )
    }
  }
}

fn show_own_input(ctx: ScriptContext) -> Input {
  let ScriptContext { purpose, transaction } = ctx
  let Transaction { inputs, .. } = transaction
  expect Spend(out_ref) = purpose
  expect Some(input) = find_input(inputs, out_ref)
  input
}

fn input_has_token(
  ctx: ScriptContext,
  policy_id: PolicyId,
  asset_name: AssetName,
) -> Bool {
  let input = show_own_input(ctx)
  let Input { output, .. } = input
  quantity_of(output.value, policy_id, asset_name) == 1
}

fn get_continuing_txn(ctx: ScriptContext) {
  let input = show_own_input(ctx)
  let Input { output, .. } = input
  let ScriptContext { transaction, .. } = ctx
  let Transaction { outputs, .. } = transaction
  expect [oneoutput] =
    list.filter(outputs, fn(o) { output.address == o.address })
  oneoutput
}

fn output_has_token(
  ctx: ScriptContext,
  policy_id: PolicyId,
  asset_name: AssetName,
) {
  let output = get_continuing_txn(ctx)
  quantity_of(output.value, policy_id, asset_name) == 1
}

fn must_be_signed_by(transaction: Transaction, vk: VerificationKeyHash) {
  list.has(transaction.extra_signatories, vk)
}

fn find_datum(datum: transaction.Datum, ctx: ScriptContext) {
  let ScriptContext { transaction, .. } = ctx
  let Transaction { datums, .. } = transaction
  when datum is {
    DatumHash(key) -> {
      expect Some(value) = get(datums, key)
      expect exact_datum: Datum = value
      exact_datum
    }
    InlineDatum(data) -> {
      expect exact_datum: Datum = data
      exact_datum
    }
    _ -> fail
  }
}

fn check_datum_for_comment(dtm: Datum, ctx: ScriptContext) {
  let output = get_continuing_txn(ctx)
  let datum = find_datum(output.datum, ctx)
  when datum.comments is {
    [] -> False
    _ -> {
      let comments_length = list.length(datum.comments)
      let comment_removed_last = list.take(datum.comments, comments_length - 1)
      let all_fields_match =
        dtm.manufacturer == datum.manufacturer && dtm.manufactuerdate == datum.manufactuerdate && dtm.expirydate == datum.expirydate && dtm.photos == datum.photos && dtm.currentowner == datum.currentowner && dtm.owners == datum.owners && comment_removed_last == dtm.comments
      all_fields_match
    }
  }
}

fn check_datum_for_transfer(dtm: Datum, ctx: ScriptContext) {
  let output = get_continuing_txn(ctx)
  let datum = find_datum(output.datum, ctx)
  let owners_length = list.length(datum.owners)
  let owners_removed_last = list.take(datum.owners, owners_length - 1)
  expect Some(last_owner) = list.last(datum.owners)
  let all_fields_match =
    dtm.manufacturer == datum.manufacturer && dtm.manufactuerdate == datum.manufactuerdate && dtm.expirydate == datum.expirydate && dtm.photos == datum.photos && last_owner == datum.currentowner && datum.currentowner != dtm.currentowner && owners_removed_last == dtm.owners && dtm.comments == datum.comments
  all_fields_match
}

//---------------------------------------------------------------- Testing Smart Contract -----------------------------------------------
fn first_user() -> VerificationKeyHash {
  #"00000000000000000000000000000000000000000000000000000000"
}

fn second_user() -> VerificationKeyHash {
  #"00000000000000000000000000000000000000000000000000000001"
}

fn initialdatum() {
  Datum {
    manufacturer: first_user(),
    manufactuerdate: 13000000,
    expirydate: 13400000,
    photos: [],
    currentowner: first_user(),
    owners: [first_user()],
    comments: [],
  }
}

fn contract_address() -> Address {
  Address {
    payment_credential: ScriptCredential(
      #"7bca7e61335570f3d7a2ee065d35e9f5ef82b6ce633047b58db30654",
    ),
    stake_credential: None,
  }
}

fn correct_datum_comment() {
  Datum { ..initialdatum(), comments: ["Great Product"] }
}

fn correct_datum_transfer() {
  Datum {
    ..initialdatum(),
    owners: [first_user(), second_user()],
    currentowner: second_user(),
  }
}

fn policy_id() {
  #"00000000000000000000000000000000000000000000000000000001"
}

fn asset_name() {
  #"00000000000000000000000000000000000000000000000000000001"
}

fn asset() {
  from_asset(policy_id(), asset_name(), 1)
}

// ------------------------- Inline datum Testing ------------------------------

// -------- Comment Testing ------------

test supplychain_test_comment_correct_datum() {
  supplychain_test(
    Comment,
    initialdatum(),
    correct_datum_comment(),
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_no_signature_from_currentowner() {
  let input_datum = Datum { ..initialdatum(), currentowner: second_user() }
  !supplychain_test(
    Comment,
    input_datum,
    correct_datum_comment(),
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_datum_manufacture_date() {
  let output_datum =
    Datum { ..correct_datum_comment(), manufactuerdate: 9878675645 }
  !supplychain_test(
    Comment,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_datum_expiry_date() {
  let output_datum = Datum { ..correct_datum_comment(), expirydate: 9878675645 }
  !supplychain_test(
    Comment,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_datum_manufacturer() {
  let output_datum =
    Datum { ..correct_datum_comment(), manufacturer: second_user() }
  !supplychain_test(
    Comment,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_datum_photos() {
  let output_datum = Datum { ..correct_datum_comment(), photos: ["Achyut"] }
  !supplychain_test(
    Comment,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_datum_current_owner() {
  let output_datum =
    Datum { ..correct_datum_comment(), currentowner: second_user() }
  !supplychain_test(
    Comment,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_datum_owners() {
  let output_datum =
    Datum { ..correct_datum_comment(), owners: [second_user()] }
  !supplychain_test(
    Comment,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_datum_comments() {
  !supplychain_test(
    Comment,
    initialdatum(),
    initialdatum(),
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_input_asset_value() {
  let input_asset_value = from_lovelace(20)
  !supplychain_test(
    Comment,
    initialdatum(),
    correct_datum_comment(),
    input_asset_value,
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_comment_incorrect_output_asset_value() {
  let output_asset_value = from_lovelace(20)
  !supplychain_test(
    Comment,
    initialdatum(),
    correct_datum_comment(),
    asset(),
    output_asset_value,
    policy_id(),
    asset_name(),
  )
}

// ------------- Transfer Testing --------------

test supplychain_test_transfer_correct_datum() {
  supplychain_test(
    Transfer,
    initialdatum(),
    correct_datum_transfer(),
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_datum_manufacture_date() {
  let output_datum =
    Datum { ..correct_datum_transfer(), manufactuerdate: 9878675645 }
  !supplychain_test(
    Transfer,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_datum_expiry_date() {
  let output_datum =
    Datum { ..correct_datum_transfer(), expirydate: 9878675645 }
  !supplychain_test(
    Transfer,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_datum_manufacturer() {
  let output_datum =
    Datum { ..correct_datum_transfer(), manufacturer: second_user() }
  !supplychain_test(
    Transfer,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_datum_photos() {
  let output_datum = Datum { ..correct_datum_transfer(), photos: ["Achyut"] }
  !supplychain_test(
    Transfer,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_datum_current_owner() {
  let output_datum =
    Datum { ..correct_datum_transfer(), currentowner: first_user() }
  !supplychain_test(
    Transfer,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_datum_owners() {
  let output_datum =
    Datum { ..correct_datum_transfer(), owners: [second_user()] }
  !supplychain_test(
    Transfer,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_datum_comments() {
  let output_datum = Datum { ..correct_datum_transfer(), comments: ["Achyut"] }
  !supplychain_test(
    Comment,
    initialdatum(),
    output_datum,
    asset(),
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_input_asset_value() {
  let input_asset_value = from_lovelace(20)
  !supplychain_test(
    Comment,
    initialdatum(),
    correct_datum_transfer(),
    input_asset_value,
    asset(),
    policy_id(),
    asset_name(),
  )
}

test supplychain_test_transfer_incorrect_output_asset_value() {
  let output_asset_value = from_lovelace(20)
  !supplychain_test(
    Transfer,
    initialdatum(),
    correct_datum_transfer(),
    asset(),
    output_asset_value,
    policy_id(),
    asset_name(),
  )
}

fn supplychain_test(
  redemer: Action,
  input_datum: Datum,
  output_datum: Datum,
  input_asset: Value,
  output_asset: Value,
  policy_id: PolicyId,
  asset_name: AssetName,
) {
  let placeholder_utxo =
    OutputReference { transaction_id: TransactionId(""), output_index: 0 }

  let input =
    Input {
      output_reference: placeholder_utxo,
      output: Output {
        address: contract_address(),
        value: input_asset,
        datum: InlineDatum(input_datum),
        reference_script: None,
      },
    }
  let output =
    Output {
      address: contract_address(),
      value: output_asset,
      datum: InlineDatum(output_datum),
      reference_script: None,
    }

  let context =
    ScriptContext {
      purpose: Spend(placeholder_utxo),
      transaction: transaction.placeholder()
        |> fn(transaction) {
             Transaction {
               ..transaction,
               extra_signatories: [first_user()],
               inputs: [input],
               outputs: [output],
             }
           },
    }
  supplychain(policy_id, asset_name, input_datum, redemer, context)
}
// ------------ Testing with datumHash --------------

// test supply_chain_transfer_correct() {
//   let datum_hash = #"00000000000000000000000000000000000000000000000000000005"
//   let data = builtin.serialise_data(correct_datum_transfer())
//   let result =
//     dict.new()
//       |> dict.insert(key: datum_hash, value: data, compare: fn(x, y) { Greater })
//   supplychain_test_datum_hash(
//     Transfer,
//     initialdatum(),
//     datum_hash,
//     asset(),
//     asset(),
//     policy_id(),
//     asset_name(),
//     result,
//   )
// }

// fn supplychain_test_datum_hash(
//   redemer: Action,
//   input_datum: Datum,
//   output_datum: Hash<Blake2b_256, Data>,
//   input_asset: Value,
//   output_asset: Value,
//   policy_id: PolicyId,
//   asset_name: AssetName,
//   datums: Dict<Hash<Blake2b_256, Data>, Data>,
// ) {
//   let placeholder_utxo =
//     OutputReference { transaction_id: TransactionId(""), output_index: 0 }

//   let input =
//     Input {
//       output_reference: placeholder_utxo,
//       output: Output {
//         address: contract_address(),
//         value: input_asset,
//         datum: InlineDatum(input_datum),
//         reference_script: None,
//       },
//     }
//   let output =
//     Output {
//       address: contract_address(),
//       value: output_asset,
//       datum: DatumHash(output_datum),
//       reference_script: None,
//     }

//   let context =
//     ScriptContext {
//       purpose: Spend(placeholder_utxo),
//       transaction: transaction.placeholder()
//         |> fn(transaction) {
//              Transaction {
//                ..transaction,
//                extra_signatories: [first_user()],
//                inputs: [input],
//                outputs: [output],
//                datums: datums,
//              }
//            },
//     }

//   supplychain(policy_id, asset_name, input_datum, redemer, context)
// }
