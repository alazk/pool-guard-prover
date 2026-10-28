//! What the issuer signs, what the program reads, and what the proof commits to.
//!
//! The issuer (a fund administrator or transfer agent; in the demo, the app's issuer route reading
//! the Google Sheet) signs one `Record` per wallet. The program verifies that signature, checks
//! that the record's limit covers the deposit, and commits `PublicValues`: everything the Newton
//! policy needs, and never the limit.
#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

/// Domain tag in front of every signed record, so an issuer signature can mean nothing else.
pub const DOMAIN: &[u8] = b"PoolGuard register v1";

/// One investor's record, as the issuer signs it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Record {
    /// keccak256 of the register's id (the sheet's CSV URL in the demo), so a record is of one register
    pub sheet: [u8; 32],
    /// the pool's hook: the record is for one pool
    pub hook: [u8; 20],
    pub wallet: [u8; 20],
    /// the most this wallet may hold in the pool, in the pool's base units; 0 when not listed
    pub limit: [u8; 32],
    pub listed: bool,
    /// when the issuer signed, unix seconds; the policy sets how fresh it must be
    pub ts: u64,
}

impl Record {
    /// keccak256(DOMAIN ‖ sheet ‖ hook ‖ wallet ‖ limit ‖ listed ‖ ts): the 32 bytes the issuer signs.
    pub fn digest(&self) -> B256 {
        let mut m = Vec::with_capacity(DOMAIN.len() + 32 + 20 + 20 + 32 + 1 + 8);
        m.extend_from_slice(DOMAIN);
        m.extend_from_slice(&self.sheet);
        m.extend_from_slice(&self.hook);
        m.extend_from_slice(&self.wallet);
        m.extend_from_slice(&self.limit);
        m.push(self.listed as u8);
        m.extend_from_slice(&self.ts.to_be_bytes());
        keccak256(&m)
    }
}

/// Everything the program reads: the signed record, its signature, and the deposit to cover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    pub record: Record,
    /// 65 bytes: r ‖ s ‖ v, v in {0, 1, 27, 28}
    pub signature: Vec<u8>,
    /// the deposit the investor is making, in the pool's base units
    pub covered: [u8; 32],
}

sol! {
    /// ABI-encoded as the proof's public values: 8 words of 32 bytes. The policy's data
    /// component reads them by position, and the Rego compares them with the intent.
    struct PublicValues {
        bytes32 sheet;
        address hook;
        address wallet;
        uint256 covered;
        bool listed;
        bool fits;
        address issuer;
        uint64 ts;
    }
}

impl PublicValues {
    pub fn new(record: &Record, covered: [u8; 32], fits: bool, issuer: Address) -> Self {
        PublicValues {
            sheet: B256::from(record.sheet),
            hook: Address::from(record.hook),
            wallet: Address::from(record.wallet),
            covered: U256::from_be_bytes(covered),
            listed: record.listed,
            fits,
            issuer,
            ts: record.ts,
        }
    }
}
