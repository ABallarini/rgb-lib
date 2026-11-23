//! Regression test for the fee of a send being paid from colored UTXOs.
//!
//! A send that spends the exact amount carried by the smallest colored UTXO leaves no spare
//! allocation slots, so its fee has to be paid by another colored UTXO, which then carries the RGB
//! change.
//!
//! On upstream `next` only UTXOs without RGB allocations are considered for the fee, so the
//! sends fail with [`Error::InsufficientAllocationSlots`]. With the fix they succeed.
//!
//! This test is red on upstream `next` and green with the fix.

use std::str::FromStr;

use bdk_wallet::bitcoin::psbt::Psbt;

use super::*;

/// Set up a sender with 11 asset units on a 350 sat UTXO and 12 on a 5,000 sat one, plus a receiver
/// with the colorable UTXOs an invoice needs.
fn setup_pair(name: &str) -> (SinglesigParty, SinglesigParty, String, Outpoint) {
    println!("setting up pair {name}");

    let mut sender = get_empty_party!();
    let mut receiver = get_empty_party!();

    send_sats_to_address(sender.get_address(), Some(6_000));
    mine(false);
    sender.list_unspents_with_sync(false);
    sender.create_utxos(false, Some(1), Some(350), 1, None);
    sender.create_utxos(false, Some(1), Some(5_000), 1, None);
    let asset = sender.issue_asset_nia(Some(&[11, 12]));

    let unspents = sender.list_unspents(false);
    // The issuance assigns the amounts in the order the colorable UTXOs are picked, which is
    // stable in the test database: 11 goes to the 350 sat UTXO and 12 to the 5,000 sat one.
    let small = unspents
        .iter()
        .find(|u| u.utxo.btc_amount == 350)
        .expect("missing 350 sat UTXO");
    assert_eq!(small.rgb_allocations.len(), 1);
    assert_eq!(small.rgb_allocations[0].assignment, Assignment::Fungible(11));
    let colored = unspents
        .iter()
        .find(|u| u.utxo.btc_amount == 5_000)
        .expect("missing 5,000 sat UTXO");
    assert_eq!(colored.rgb_allocations.len(), 1);
    assert_eq!(colored.rgb_allocations[0].assignment, Assignment::Fungible(12));
    let colored_outpoint = colored.utxo.outpoint.clone();

    send_sats_to_address(receiver.get_address(), Some(6_000));
    mine(false);
    receiver.list_unspents_with_sync(false);
    receiver.create_utxos(false, Some(1), Some(400), 1, None);
    receiver.create_utxos(false, Some(1), Some(400), 1, None);
    receiver.create_utxos(false, Some(1), Some(400), 1, None);

    (sender, receiver, asset.asset_id, colored_outpoint)
}

fn recipient_map(
    receiver: &mut SinglesigParty,
    asset_id: &str,
    amount: u64,
) -> HashMap<String, Vec<Recipient>> {
    let receive_data = receiver.blind_receive_with_endpoints(None, vec![]);
    HashMap::from([(
        asset_id.to_string(),
        vec![Recipient {
            recipient_id: receive_data.recipient_id,
            witness_data: None,
            assignment: Assignment::Fungible(amount),
            transport_endpoints: vec![],
            public_key: None,
            encryption: Encryption::Optional,
            expiration_timestamp: None,
        }],
    )])
}

fn spend_outpoints(psbt: &str) -> Vec<Outpoint> {
    Psbt::from_str(psbt)
        .unwrap()
        .unsigned_tx
        .input
        .iter()
        .map(|i| Outpoint::from(i.previous_output))
        .collect()
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn insufficient_fee_exact_amount_uses_colored_utxo() {
    initialize();

    // the 11 units are carried by the 350 sat UTXO: the fee needs the 5,000 sat colored UTXO
    let (mut sender_a, mut receiver_a, asset_id_a, colored_outpoint_a) = setup_pair("a");
    let recipient_map_a = recipient_map(&mut receiver_a, &asset_id_a, 11);
    let result_a = sender_a.send_begin_result_with_fee_rate(&recipient_map_a, 10);
    assert!(result_a.is_ok(), "{result_a:?}");
    let inputs_a = spend_outpoints(&result_a.unwrap().psbt);
    assert_eq!(inputs_a.len(), 2);
    assert!(inputs_a.contains(&colored_outpoint_a));

    // the 12 units are carried by the 5,000 sat UTXO, which has to be spent
    let (mut sender_b, mut receiver_b, asset_id_b, colored_outpoint_b) = setup_pair("b");
    let recipient_map_b = recipient_map(&mut receiver_b, &asset_id_b, 12);
    let result_b = sender_b.send_begin_result_with_fee_rate(&recipient_map_b, 10);
    assert!(result_b.is_ok(), "{result_b:?}");
    let inputs_b = spend_outpoints(&result_b.unwrap().psbt);
    assert!(inputs_b.contains(&colored_outpoint_b));
}

