/**
 * BIP-125 Replace-By-Fee (RBF) policy utilities.
 *
 * Mirrors bitcoin-core/src/util/rbf.cpp and bitcoin-core/src/policy/rbf.cpp.
 *
 * Gates implemented here (matching Core's function names):
 *   signalsOptInRBF   — util/rbf.cpp:SignalsOptInRBF
 *   entriesAndTxidsDisjoint — policy/rbf.cpp:EntriesAndTxidsDisjoint
 *
 * The remaining gates (HasNoNewUnconfirmed, PaysForRBF, GetEntriesForConflicts)
 * are implemented inline in Mempool.addTransaction() in mempool.ts, where the
 * full mempool state is available.
 *
 * Constant:
 *   MAX_BIP125_RBF_SEQUENCE = 0xfffffffd  (util/rbf.h:MAX_BIP125_RBF_SEQUENCE)
 *   MAX_REPLACEMENT_CANDIDATES = 100      (policy/rbf.h:MAX_REPLACEMENT_CANDIDATES)
 */

import type { Transaction } from "../validation/tx.js";

/**
 * Maximum sequence number that signals opt-in RBF (BIP-125).
 * Any input with nSequence <= MAX_BIP125_RBF_SEQUENCE signals opt-in.
 * Mirrors bitcoin-core/src/util/rbf.h:MAX_BIP125_RBF_SEQUENCE.
 *
 * Note: 0xfffffffd = SEQUENCE_FINAL - 2 = 4294967293.
 * SEQUENCE_FINAL-1 (0xfffffffe) is reserved for nLockTime use without RBF signaling.
 * JS Number can represent this exactly (< 2^53); no BigInt or >>> 0 needed.
 */
export const MAX_BIP125_RBF_SEQUENCE = 0xfffffffd; // 4294967293

/**
 * Maximum number of unique clusters (or legacy: transactions) that can be
 * affected by a single RBF replacement.
 * Mirrors bitcoin-core/src/policy/rbf.h:MAX_REPLACEMENT_CANDIDATES.
 */
export const MAX_REPLACEMENT_CANDIDATES = 100;

/**
 * Determine whether a transaction signals opt-in RBF according to BIP-125.
 *
 * A transaction signals opt-in RBF if ANY of its inputs has nSequence <=
 * MAX_BIP125_RBF_SEQUENCE (0xfffffffd). All inputs must opt out (nSequence >
 * 0xfffffffd) for the transaction to be considered non-signaling.
 *
 * "All rather than just one is for the sake of multi-party protocols, where we
 *  don't want a single party to be able to disable replacement by opting out in
 *  their own input." — bitcoin-core/src/util/rbf.h
 *
 * Mirrors bitcoin-core/src/util/rbf.cpp:SignalsOptInRBF.
 *
 * IMPORTANT: sequence is a uint32 stored as JS number. 0xfffffffd = 4294967293
 * is within JS safe-integer range, so plain `<=` comparison is correct.
 * No signed-int hazard here (bit-ops would be hazardous, comparison is not).
 */
export function signalsOptInRBF(tx: Transaction): boolean {
  for (const input of tx.inputs) {
    if (input.sequence <= MAX_BIP125_RBF_SEQUENCE) {
      return true;
    }
  }
  return false;
}

/**
 * RBF opt-in state for an unconfirmed transaction.
 * Mirrors bitcoin-core/src/policy/rbf.h:RBFTransactionState.
 */
export enum RBFTransactionState {
  /** Unconfirmed tx that does not signal RBF and is not in the mempool. */
  UNKNOWN = "unknown",
  /** Either this tx or a mempool ancestor signals RBF (BIP-125). */
  REPLACEABLE_BIP125 = "yes",
  /** Neither this tx nor a mempool ancestor signals RBF. */
  FINAL = "no",
}

/**
 * Determine the RBF opt-in state for a transaction, considering mempool
 * ancestors. Mirrors bitcoin-core/src/policy/rbf.cpp:IsRBFOptIn.
 *
 * @param tx            The transaction to check.
 * @param isInMempool   Whether tx is currently in the mempool.
 * @param ancestorTxs   Iterable of the transaction's mempool ancestors.
 */
export function isRBFOptIn(
  tx: Transaction,
  isInMempool: boolean,
  ancestorTxs: Iterable<Transaction>
): RBFTransactionState {
  // Check the transaction itself first.
  if (signalsOptInRBF(tx)) {
    return RBFTransactionState.REPLACEABLE_BIP125;
  }

  // If not in mempool we can't be sure we know all ancestors.
  if (!isInMempool) {
    return RBFTransactionState.UNKNOWN;
  }

  // Walk ancestors: if any signals RBF, the tx is replaceable via inheritance.
  for (const ancestor of ancestorTxs) {
    if (signalsOptInRBF(ancestor)) {
      return RBFTransactionState.REPLACEABLE_BIP125;
    }
  }

  return RBFTransactionState.FINAL;
}

/**
 * Check that the ancestors of the replacement transaction are disjoint from
 * the set of direct conflicts (transactions being replaced).
 *
 * This prevents a tx from being an ancestor of its own replacement conflicts —
 * e.g. a replacement that indirectly spends an output of a tx it is trying
 * to replace, which would be topologically impossible after eviction.
 *
 * Mirrors bitcoin-core/src/policy/rbf.cpp:EntriesAndTxidsDisjoint.
 *
 * @param replacementAncestorTxids  Set of txid-hex strings for all mempool
 *                                  ancestors of the replacement transaction.
 * @param directConflictTxids       Set of txid-hex strings for the mempool
 *                                  entries directly conflicting with the
 *                                  replacement (the transactions to be evicted).
 * @param replacementTxidHex        Txid of the replacement, for error messages.
 * @returns Error string if the sets intersect, null if disjoint.
 */
export function entriesAndTxidsDisjoint(
  replacementAncestorTxids: ReadonlySet<string>,
  directConflictTxids: ReadonlySet<string>,
  replacementTxidHex: string
): string | null {
  for (const ancestorTxidHex of replacementAncestorTxids) {
    if (directConflictTxids.has(ancestorTxidHex)) {
      return `${replacementTxidHex} spends conflicting transaction ${ancestorTxidHex} (BIP-125 Rule 2 / EntriesAndTxidsDisjoint)`;
    }
  }
  return null;
}
