// Hand-written TypeScript types for the lattice-core WASM bindings.
//
// These match the `#[wasm_bindgen]` exports in
// `crates/lattice-core/src/wasm.rs`. After running `wasm-bindgen` the
// auto-generated `.d.ts` will live at `src/wasm/lattice_core.d.ts`;
// this file is the typed view callers import from
// `import { LatticeWasm } from "./lattice"`.

/// Initialize the WASM module: panic hook + crypto subsystem.
/// Idempotent.
export function init(): Promise<void>;

export interface SigningKeypair {
  /// 32-byte user_id, base64 (BLAKE3 of the Ed25519 pubkey).
  user_id_b64: string;
  /// Packed `ed25519_pub(32) || ml_dsa_pub(1952)`, base64.
  sig_pk_b64: string;
  /// Packed `ed25519_sk(32) || ml_dsa_seed(32)`, base64.
  sig_sk_b64: string;
}

export function generateSigningKeypair(): SigningKeypair;
export function sign(sig_sk_b64: string, message_b64: string): string;
export function verify(
  sig_pk_b64: string,
  sig_b64: string,
  message_b64: string,
): boolean;

export interface KemKeypair {
  /// `x25519_pub(32) || ml_kem_ek(1184)`, base64.
  pk_b64: string;
  /// `x25519_sk(32) || ml_kem_dk(2400)`, base64.
  sk_b64: string;
}

export function generateKemKeypair(): KemKeypair;

export interface KemEncap {
  /// `x25519_eph_pk(32) || ml_kem_ct(1088)`, base64.
  ciphertext_b64: string;
  /// 32-byte session key, base64.
  session_key_b64: string;
  /// 32-byte confirmation tag, base64.
  confirmation_b64: string;
}

export function hybridKemEncap(
  peer_pk_b64: string,
  info_b64: string,
): KemEncap;

export interface KemShared {
  session_key_b64: string;
  confirmation_b64: string;
}

export function hybridKemDecap(
  sk_b64: string,
  ciphertext_b64: string,
  info_b64: string,
): KemShared;

export function version(): string;
