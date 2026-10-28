# Pool Guard prover

The free prover behind the SP1 route of [Pool Guard](https://newton-pool-guard.vercel.app), a
Newton Protocol demo for Uniswap Permissioned Pools. An issuer signs a wallet's allowlist record
(listed, and up to what limit); the SP1 program here checks that signature and that the limit
covers the deposit, and commits only the answer: the wallet, the amount, listed, fits, the
issuer and the time. The Newton operators verify the proof through Succinct's SP1 verifier on
Sepolia before they authorize the deposit. The limit itself never leaves the proof.

- `sp1/program`: the zkVM program. Its verifying key is in `sp1/elf/vkey.json`.
- `sp1/types`: the record and the public values.
- `sp1/prover`: `pg-prover`, the command line that makes a proof.
- `.github/workflows/prove.yml`: one Groth16 proof per run on a hosted runner. The console starts
  a run with the request sealed under the repo's `PROVER_INPUT_KEY` secret, and the proof lands
  on the rolling `proofs` release.
- `.github/workflows/prover.yml`: builds `pg-prover` as a static Linux binary on the rolling
  `pg-prover` release.

Generated from the main Pool Guard repo by `script/make-prover-repo.sh`; change it there.
