use aiken/dict.{get}
use aiken/hash.{Blake2b_224, Hash}
use aiken/list
use aiken/transaction.{
  DatumHash, InlineDatum, Input, ScriptContext, Spend, Transaction, find_input,
}
use aiken/transaction/credential.{VerificationKey}
use aiken/transaction/value.{AssetName, PolicyId, quantity_of}

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
  let comments_length = list.length(datum.comments)
  let comment_removed_last = list.take(datum.comments, comments_length - 1)
  let all_fields_match =
    dtm.manufacturer == datum.manufacturer && dtm.manufactuerdate == datum.manufactuerdate && dtm.expirydate == datum.expirydate && dtm.photos == datum.photos && dtm.currentowner == datum.currentowner && dtm.owners == datum.owners && comment_removed_last == dtm.comments
  all_fields_match
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
