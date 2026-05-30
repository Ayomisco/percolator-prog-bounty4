//! Phase 3A.0 — 5-program assembled cross-cut SMOKE (load feasibility + token
//! coexistence). See `~/wrapper-engine-deep-audit/phase3a_crosscut_design.md`.
//!
//! This is the FIRST time wrapper + matcher + NFT + stake + Token-2022 are mounted
//! into ONE litesvm-0.1 instance. It ships before the economic spine (3A.1) to
//! de-risk the genuine unknowns:
//!   * Can all five `.so`s co-load? (stake is GREENFIELD — loaded by ZERO wrapper
//!     tests before now; its id-allowlisting under litesvm 0.1 was unverified.)
//!   * Does `with_spl_programs()` under 0.1 mount BOTH classic SPL (`Tokenkeg`) and
//!     Token-2022 (`TokenzQd`) as distinct, runnable programs?
//!   * Does the wrapper vault accept ONLY classic SPL (`verify_token_program`,
//!     `v16_program.rs:12391`)?
//!
//! # Anti-hollow discipline (carried from Phase 2.E)
//! Each test carries a load-bearing EXECUTED guard, not a silent mount check:
//!   * `coload_executable_and_distinct` — mounts all 7 program accounts and proves
//!     each is `executable`; proves classic ≠ Token-2022 (distinct roles).
//!   * `stake_program_executes_under_litesvm_01` — REAL invocation of the stake
//!     `.so`; an empty-data tx must fail with the stake program's OWN
//!     `InvalidInstructionData` (its `StakeInstruction::unpack` `split_first`
//!     reject), proving the sbpf-v0 stake binary actually runs under the VM — NOT
//!     a loader rejection.
//!   * `classic_and_token2022_mints_coexist` — REAL `InitializeMint2` on EACH token
//!     program in the SAME assembled instance; both succeed and the resulting mints
//!     are owned by their respective (distinct) programs.
//!   * `wrapper_vault_gate_requires_classic_token_program` — REAL `CreateLpVault`
//!     (tag 65) reaching `verify_token_program`: Token-2022 → `Custom(13)`
//!     (`InvalidTokenProgram`) at the gate; classic SPL passes the gate and fails
//!     DOWNSTREAM at market-magic parse (a different code), isolating the gate as
//!     the operative token-program discriminator.

mod common;
use common::*;

use percolator_prog::ix::Instruction as ProgInstruction;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction, system_program,
};
use spl_token::state::Mint;

/// `InvalidTokenProgram` — `PercolatorError` ordinal 13, mapped via
/// `From<PercolatorError> for ProgramError => Custom(value as u32)`
/// (`v16_program.rs:189,231-234`).
const INVALID_TOKEN_PROGRAM: u32 = 13;
/// `NotInitialized` — ordinal 3. The post-gate market-magic parse on a zeroed
/// market returns this (verified by diagnostic at 3A.0), proving the classic
/// token program got PAST `verify_token_program`.
const NOT_INITIALIZED: u32 = 3;

// ── 3A.0-A: all five co-load executable + distinct token roles ──────────────

#[test]
fn x0_smoke_coload_executable_and_distinct() {
    let matcher_id = Pubkey::new_unique();
    let svm = assemble_five_program_svm(matcher_id);

    for (label, id) in [
        ("wrapper@MAINNET", PERCOLATOR_MAINNET),
        ("nft", NFT_PROGRAM_ID),
        ("stake", STAKE_ID),
        ("matcher", matcher_id),
        ("classic-spl-token", spl_token_classic_id()),
        ("token-2022", TOKEN_2022),
        ("ata", ATA_PROGRAM),
    ] {
        let acct = svm
            .get_account(&id)
            .unwrap_or_else(|| panic!("{label} ({id}) program account missing after load"));
        assert!(
            acct.executable,
            "{label} ({id}) must be mounted as an executable program"
        );
    }

    // Distinct roles — the vault uses classic only; Token-2022 is the NFT mint side.
    assert_ne!(
        spl_token_classic_id(),
        TOKEN_2022,
        "classic SPL and Token-2022 must be distinct programs"
    );
}

// ── 3A.0-B: the greenfield stake .so actually executes under litesvm 0.1 ────

#[test]
fn x0_smoke_stake_program_executes_under_litesvm_01() {
    let matcher_id = Pubkey::new_unique();
    let mut svm = assemble_five_program_svm(matcher_id);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

    // Empty instruction data → `StakeInstruction::unpack` reaches
    // `data.split_first().ok_or(ProgramError::InvalidInstructionData)`
    // (`instruction.rs:211-213`). A program-level `InvalidInstructionData` (NOT a
    // loader rejection) proves the stake sbpf-v0 binary entered and ran.
    let stake_ix = Instruction {
        program_id: STAKE_ID,
        accounts: vec![],
        data: vec![],
    };
    let res = send_ixs(&mut svm, &payer, vec![stake_ix], &[]);
    assert_instruction_error(
        &res,
        InstructionError::InvalidInstructionData,
        "greenfield stake .so executes (empty-data decode reject)",
    );
}

// ── 3A.0-C: classic SPL + Token-2022 mints coexist in one instance ──────────

#[test]
fn x0_smoke_classic_and_token2022_mints_coexist() {
    let matcher_id = Pubkey::new_unique();
    let mut svm = assemble_five_program_svm(matcher_id);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    let space = Mint::LEN; // 82 — a no-extension mint (identical base layout in both)

    // (1) Real classic-SPL InitializeMint2 via the canonical builder.
    let classic_mint = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    let classic_create = system_instruction::create_account(
        &payer.pubkey(),
        &classic_mint.pubkey(),
        lamports,
        space as u64,
        &spl_token_classic_id(),
    );
    let classic_init = spl_token::instruction::initialize_mint2(
        &spl_token_classic_id(),
        &classic_mint.pubkey(),
        &payer.pubkey(),
        None,
        0,
    )
    .unwrap();
    send_ixs(
        &mut svm,
        &payer,
        vec![classic_create, classic_init],
        &[&classic_mint],
    )
    .expect("classic SPL mint initializes in the assembled 5-program instance");

    let classic_acct = svm
        .get_account(&classic_mint.pubkey())
        .expect("classic mint exists");
    assert_eq!(
        classic_acct.owner,
        spl_token_classic_id(),
        "classic mint owned by Tokenkeg"
    );
    let unpacked = Mint::unpack(&classic_acct.data).expect("classic mint unpacks");
    assert!(unpacked.is_initialized, "classic mint is initialized");

    // (2) Real Token-2022 InitializeMint2 (hand-encoded) on a fresh account, in the
    // SAME svm. Wire: tag(1)=20, decimals(1)=0, mint_authority(32), freeze_opt(1)=0.
    let t22_mint = Keypair::new();
    let t22_create = system_instruction::create_account(
        &payer.pubkey(),
        &t22_mint.pubkey(),
        lamports,
        space as u64,
        &TOKEN_2022,
    );
    let mut t22_init_data = Vec::with_capacity(35);
    t22_init_data.push(20u8); // IX_INITIALIZE_MINT2
    t22_init_data.push(0u8); // decimals
    t22_init_data.extend_from_slice(payer.pubkey().as_ref()); // mint authority
    t22_init_data.push(0u8); // freeze authority = None
    let t22_init = Instruction {
        program_id: TOKEN_2022,
        accounts: vec![AccountMeta::new(t22_mint.pubkey(), false)],
        data: t22_init_data,
    };
    send_ixs(&mut svm, &payer, vec![t22_create, t22_init], &[&t22_mint])
        .expect("Token-2022 mint initializes in the assembled 5-program instance");

    let t22_acct = svm
        .get_account(&t22_mint.pubkey())
        .expect("token-2022 mint exists");
    assert_eq!(t22_acct.owner, TOKEN_2022, "token-2022 mint owned by TokenzQd");
    // Layout-explicit init check (offset 45 = `is_initialized`) — avoids relying on
    // classic unpack semantics for a Token-2022-owned account.
    assert!(
        t22_acct.data.len() >= 46 && t22_acct.data[45] == 1,
        "token-2022 mint is initialized"
    );
}

// ── 3A.0-D: wrapper vault gate requires classic SPL (verify_token_program) ──

/// `CreateLpVault` (tag 65). `handle_create_lp_vault` (`v16_program.rs:5266`)
/// calls `verify_token_program` at :5286 after only account-flag + owner checks,
/// so it is the lightest honest path to the gate.
fn create_lp_vault_ix(
    market: Pubkey,
    registry: Pubkey,
    mint: Pubkey,
    admin: Pubkey,
    token_program: Pubkey,
) -> Instruction {
    Instruction {
        program_id: PERCOLATOR_MAINNET,
        accounts: vec![
            AccountMeta::new(admin, true),                        // 0 admin (signer, writable)
            AccountMeta::new_readonly(market, false),             // 1 market (owner==MAINNET; read)
            AccountMeta::new(registry, false),                    // 2 registry PDA (writable)
            AccountMeta::new(mint, false),                        // 3 mint PDA (writable)
            AccountMeta::new_readonly(system_program::ID, false), // 4 system program
            AccountMeta::new_readonly(token_program, false),      // 5 token program (under test)
        ],
        data: ProgInstruction::CreateLpVault {
            fee_share_bps: 0,
            redemption_cooldown_slots: 0,
            oi_reservation_threshold_bps: 0,
            domain: 0,
        }
        .encode(),
    }
}

#[test]
fn x0_smoke_wrapper_vault_gate_requires_classic_token_program() {
    let matcher_id = Pubkey::new_unique();
    let mut svm = assemble_five_program_svm(matcher_id);
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    // Market owned by the wrapper (passes `expect_owner(market, program_id=MAINNET)`)
    // but with zeroed content (so the classic-token positive path fails downstream
    // at the magic parse, not at the gate).
    let market = Pubkey::new_unique();
    let market_len = percolator_prog::state::market_account_len_for_capacity(1).unwrap();
    svm.set_account(
        market,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; market_len],
            owner: PERCOLATOR_MAINNET,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let registry = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    // NEGATIVE — Token-2022 supplied where the vault demands classic SPL.
    let res_t22 = send_ixs(
        &mut svm,
        &payer,
        vec![create_lp_vault_ix(market, registry, mint, payer.pubkey(), TOKEN_2022)],
        &[],
    );
    assert_custom(
        res_t22,
        INVALID_TOKEN_PROGRAM,
        "wrapper vault rejects Token-2022 as the token program",
    );

    // POSITIVE — classic SPL passes the gate; the tx fails DOWNSTREAM at the
    // zeroed-market parse with `NotInitialized` (Custom 3), NOT `InvalidTokenProgram`
    // — proving classic SPL is accepted and execution proceeded past the gate into
    // market parsing. Two different operative codes at two different stages isolate
    // `verify_token_program` as the token-program discriminator.
    let res_classic = send_ixs(
        &mut svm,
        &payer,
        vec![create_lp_vault_ix(
            market,
            registry,
            mint,
            payer.pubkey(),
            spl_token_classic_id(),
        )],
        &[],
    );
    assert_custom(
        res_classic,
        NOT_INITIALIZED,
        "wrapper vault accepts classic SPL (gate passed → fails downstream at market parse)",
    );
}
