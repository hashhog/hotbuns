/**
 * Consensus error codes for block and transaction validation failures.
 *
 * These match Bitcoin Core rejection codes and are used for proper error
 * propagation in the P2P layer.
 */

/**
 * Error thrown when a transaction or block violates consensus rules.
 */
export class ConsensusError extends Error {
  readonly code: ConsensusErrorCode;
  readonly rejectCode: number;

  constructor(code: ConsensusErrorCode, message?: string) {
    super(message ?? code);
    this.name = "ConsensusError";
    this.code = code;
    this.rejectCode = REJECT_CODES[code] ?? 0x10; // Default to REJECT_INVALID
  }
}

/**
 * Consensus error codes.
 */
export enum ConsensusErrorCode {
  // Transaction errors
  MISSING_INPUTS = "MISSING_INPUTS",
  PREMATURE_COINBASE_SPEND = "PREMATURE_COINBASE_SPEND",
  INSUFFICIENT_FEE = "INSUFFICIENT_FEE",
  DUPLICATE_INPUTS = "DUPLICATE_INPUTS",
  BAD_TXNS_OVERSIZE = "BAD_TXNS_OVERSIZE",
  BAD_TXNS_VOUT_EMPTY = "BAD_TXNS_VOUT_EMPTY",
  BAD_TXNS_VOUT_NEGATIVE = "BAD_TXNS_VOUT_NEGATIVE",
  BAD_TXNS_VOUT_TOOLARGE = "BAD_TXNS_VOUT_TOOLARGE",
  BAD_TXNS_TXOUTTOTAL_TOOLARGE = "BAD_TXNS_TXOUTTOTAL_TOOLARGE",
  BAD_TXNS_VIN_EMPTY = "BAD_TXNS_VIN_EMPTY",
  BAD_TXNS_PREVOUT_NULL = "BAD_TXNS_PREVOUT_NULL",
  INPUTS_NOT_EQUAL_OUTPUTS = "INPUTS_NOT_EQUAL_OUTPUTS",

  // Script errors
  SCRIPT_VERIFY_FLAG_FAILED = "SCRIPT_VERIFY_FLAG_FAILED",
  CHECKSIG_FAILED = "CHECKSIG_FAILED",
  CHECKMULTISIG_FAILED = "CHECKMULTISIG_FAILED",
  WITNESS_PROGRAM_MISMATCH = "WITNESS_PROGRAM_MISMATCH",

  // Block errors
  BAD_MERKLE_ROOT = "BAD_MERKLE_ROOT",
  BAD_WITNESS_COMMITMENT = "BAD_WITNESS_COMMITMENT",
  BAD_BLOCK_WEIGHT = "BAD_BLOCK_WEIGHT",
  BAD_SIGOPS_COST = "BAD_SIGOPS_COST",
  BLOCK_TIME_TOO_NEW = "BLOCK_TIME_TOO_NEW",
  BLOCK_TIME_TOO_OLD = "BLOCK_TIME_TOO_OLD",
  INVALID_POW = "INVALID_POW",
  NO_COINBASE = "NO_COINBASE",
  MULTIPLE_COINBASE = "MULTIPLE_COINBASE",
  BAD_COINBASE_HEIGHT = "BAD_COINBASE_HEIGHT",
  BAD_COINBASE_VALUE = "BAD_COINBASE_VALUE",

  // Sequence lock errors
  SEQUENCE_LOCK_NOT_SATISFIED = "SEQUENCE_LOCK_NOT_SATISFIED",

  // Checkpoint errors
  CHECKPOINT_MISMATCH = "CHECKPOINT_MISMATCH",

  // BIP-30: block would overwrite an existing unspent output
  BIP30_DUPLICATE_OUTPUT = "BIP30_DUPLICATE_OUTPUT",
}

/**
 * BIP 61 reject message codes.
 */
const REJECT_CODES: Record<ConsensusErrorCode, number> = {
  [ConsensusErrorCode.MISSING_INPUTS]: 0x10,
  [ConsensusErrorCode.PREMATURE_COINBASE_SPEND]: 0x10,
  [ConsensusErrorCode.INSUFFICIENT_FEE]: 0x42,
  [ConsensusErrorCode.DUPLICATE_INPUTS]: 0x10,
  [ConsensusErrorCode.BAD_TXNS_OVERSIZE]: 0x10,
  [ConsensusErrorCode.BAD_TXNS_VOUT_EMPTY]: 0x10,
  [ConsensusErrorCode.BAD_TXNS_VOUT_NEGATIVE]: 0x10,
  [ConsensusErrorCode.BAD_TXNS_VOUT_TOOLARGE]: 0x10,
  [ConsensusErrorCode.BAD_TXNS_TXOUTTOTAL_TOOLARGE]: 0x10,
  [ConsensusErrorCode.BAD_TXNS_VIN_EMPTY]: 0x10,
  [ConsensusErrorCode.BAD_TXNS_PREVOUT_NULL]: 0x10,
  [ConsensusErrorCode.INPUTS_NOT_EQUAL_OUTPUTS]: 0x10,
  [ConsensusErrorCode.SCRIPT_VERIFY_FLAG_FAILED]: 0x10,
  [ConsensusErrorCode.CHECKSIG_FAILED]: 0x10,
  [ConsensusErrorCode.CHECKMULTISIG_FAILED]: 0x10,
  [ConsensusErrorCode.WITNESS_PROGRAM_MISMATCH]: 0x10,
  [ConsensusErrorCode.BAD_MERKLE_ROOT]: 0x10,
  [ConsensusErrorCode.BAD_WITNESS_COMMITMENT]: 0x10,
  [ConsensusErrorCode.BAD_BLOCK_WEIGHT]: 0x10,
  [ConsensusErrorCode.BAD_SIGOPS_COST]: 0x10,
  [ConsensusErrorCode.BLOCK_TIME_TOO_NEW]: 0x10,
  [ConsensusErrorCode.BLOCK_TIME_TOO_OLD]: 0x10,
  [ConsensusErrorCode.INVALID_POW]: 0x10,
  [ConsensusErrorCode.NO_COINBASE]: 0x10,
  [ConsensusErrorCode.MULTIPLE_COINBASE]: 0x10,
  [ConsensusErrorCode.BAD_COINBASE_HEIGHT]: 0x10,
  [ConsensusErrorCode.BAD_COINBASE_VALUE]: 0x10,
  [ConsensusErrorCode.SEQUENCE_LOCK_NOT_SATISFIED]: 0x10,
  [ConsensusErrorCode.CHECKPOINT_MISMATCH]: 0x10,
  [ConsensusErrorCode.BIP30_DUPLICATE_OUTPUT]: 0x10,
};

/**
 * Maps a ConsensusErrorCode or free-form validation error string to the
 * canonical BIP-22 submitblock result string.
 *
 * BIP-22: https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki
 * Reference: Bitcoin Core BIP22ValidationResult() in src/rpc/mining.cpp
 *
 * Returns null on success; a short ASCII reason string on rejection.
 */
export function bip22Result(code: ConsensusErrorCode | string | null | undefined): string | null {
  if (code === null || code === undefined) {
    return null; // success
  }

  switch (code) {
    // Block-level errors
    case ConsensusErrorCode.INVALID_POW:
      return "high-hash";
    case ConsensusErrorCode.BAD_MERKLE_ROOT:
      return "bad-txnmrklroot";
    case ConsensusErrorCode.BAD_WITNESS_COMMITMENT:
      return "bad-witness-merkle-match";
    case ConsensusErrorCode.BAD_COINBASE_VALUE:
      return "bad-cb-amount";
    case ConsensusErrorCode.BAD_SIGOPS_COST:
      return "bad-blk-sigops";
    case ConsensusErrorCode.BAD_COINBASE_HEIGHT:
      return "bad-cb-height";
    case ConsensusErrorCode.BLOCK_TIME_TOO_OLD:
      return "time-too-old";
    case ConsensusErrorCode.BLOCK_TIME_TOO_NEW:
      return "time-too-new";

    // Transaction errors
    // Negative output value (consensus/tx_check.cpp::CheckTransaction — Core parity)
    case ConsensusErrorCode.BAD_TXNS_VOUT_NEGATIVE:
      return "bad-txns-vout-negative";
    case ConsensusErrorCode.DUPLICATE_INPUTS:
      return "bad-txns-duplicate";
    case ConsensusErrorCode.MISSING_INPUTS:
      return "bad-txns-inputs-missingorspent";
    case ConsensusErrorCode.SCRIPT_VERIFY_FLAG_FAILED:
    case ConsensusErrorCode.CHECKSIG_FAILED:
    case ConsensusErrorCode.CHECKMULTISIG_FAILED:
    case ConsensusErrorCode.WITNESS_PROGRAM_MISMATCH:
      return "mandatory-script-verify-flag-failed";
    case ConsensusErrorCode.SEQUENCE_LOCK_NOT_SATISFIED:
      return "bad-txns-nonfinal";

    default:
      break;
  }

  // For free-form error strings (from validateBlock / connectBlock), match
  // on substrings in the same precedence order as Bitcoin Core's reject reasons.
  const s = String(code).toLowerCase();

  if (s === "bad-cb-height") return "bad-cb-height"; // already canonical
  if (s === "bad-cb-length") return "bad-cb-length"; // already canonical
  if (s === "inconclusive") return "inconclusive";
  if (s === "duplicate") return "duplicate";
  if (s === "duplicate-invalid") return "duplicate-invalid";

  if (s.includes("high-hash") || s.includes("proof of work") || s.includes("does not meet target")) {
    return "high-hash";
  }
  if (s.includes("merkle root mismatch") || s.includes("bad-txnmrklroot")) {
    return "bad-txnmrklroot";
  }
  if (s.includes("witness commitment") || s.includes("bad-witness-merkle-match")) {
    return "bad-witness-merkle-match";
  }
  if (s.includes("coinbase value") || s.includes("bad-cb-amount") || s.includes("subsidy")) {
    return "bad-cb-amount";
  }
  if (s.includes("sigop") || s.includes("bad-blk-sigops")) {
    return "bad-blk-sigops";
  }
  if (s.includes("bad-cb-height") || s.includes("coinbase height")) {
    return "bad-cb-height";
  }
  if (s.includes("non-final") || s.includes("nonfinal") || s.includes("not final") || s.includes("bad-txns-nonfinal")) {
    return "bad-txns-nonfinal";
  }
  if (s.includes("duplicate") || s.includes("bad-txns-duplicate")) {
    return "bad-txns-duplicate";
  }
  if (s.includes("missing") && s.includes("input")) {
    return "bad-txns-inputs-missingorspent";
  }
  // Negative output value: validateTxBasic returns "Negative output value" (tx.ts)
  // which arrives here as "transaction N: negative output value" after wrapping.
  // Mirrors consensus/tx_check.cpp::CheckTransaction.
  if (s.includes("negative output")) {
    return "bad-txns-vout-negative";
  }
  if (
    s.includes("script") ||
    s.includes("mandatory-script-verify-flag-failed") ||
    s.includes("checksig") ||
    s.includes("tapscript") ||
    s.includes("witness program")
  ) {
    return "mandatory-script-verify-flag-failed";
  }
  if (s.includes("time-too-old") || (s.includes("timestamp") && s.includes("too old"))) {
    return "time-too-old";
  }
  if (s.includes("time-too-new") || (s.includes("timestamp") && s.includes("too far"))) {
    return "time-too-new";
  }
  if (s.includes("weight") || s.includes("oversize")) {
    return "bad-blk-length";
  }

  return "rejected";
}
