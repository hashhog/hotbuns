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
};
