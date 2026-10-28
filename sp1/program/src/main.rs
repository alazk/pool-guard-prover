//! The Pool Guard register program. Reads a signed record and a deposit, checks the signature is
//! the issuer's and the limit covers the deposit, and commits only what the policy needs.
//!
//! What stays private: the limit. What becomes public: sheet, hook, wallet, the deposit, whether
//! the wallet is listed, whether the deposit fits, who signed, and when.
//!
//! Fails closed: a bad signature or a malformed record stops the program, so no proof exists.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{keccak256, Address, U256};
use alloy_sol_types::SolValue;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use pool_guard_types::{Input, PublicValues};

pub fn main() {
    let input: Input = sp1_zkvm::io::read();

    // the signer: recover from the 65-byte signature over the record's digest
    assert_eq!(input.signature.len(), 65, "signature must be 65 bytes");
    let (rs, v) = input.signature.split_at(64);
    let sig = Signature::from_slice(rs).expect("malformed signature");
    let v = match v[0] { 0 | 27 => 0u8, 1 | 28 => 1u8, _ => panic!("bad recovery id") };
    let rid = RecoveryId::from_byte(v).expect("bad recovery id");
    let digest = input.record.digest();
    let key = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, rid).expect("signature does not verify");
    let pubkey = key.to_encoded_point(false);
    let issuer = Address::from_slice(&keccak256(&pubkey.as_bytes()[1..])[12..]);

    // the check: a listed wallet's limit covers the deposit; an unlisted wallet covers nothing
    let limit = U256::from_be_bytes(input.record.limit);
    let covered = U256::from_be_bytes(input.covered);
    let fits = input.record.listed && limit >= covered;

    let out = PublicValues::new(&input.record, input.covered, fits, issuer);
    sp1_zkvm::io::commit_slice(&out.abi_encode());
}
