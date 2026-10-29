/**
 * Startup parsing of Core's `-fallbackfee=<amount>` (BTC/kvB).
 *
 * Reference: bitcoin-core/src/util/moneystr.cpp ParseMoney and
 * bitcoin-core/src/wallet/wallet.cpp (CWallet::Create, "-fallbackfee").
 */
import { HIGH_TX_FEE_PER_KB } from "./wallet.js";

const COIN = 100_000_000n;
const MAX_MONEY = 21_000_000n * COIN;

/** Core IsSpace: the C locale whitespace set. */
function isSpace(c: string): boolean {
  return c === " " || c === "\f" || c === "\n" || c === "\r" || c === "\t" || c === "\v";
}

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= "0" && c <= "9";
}

/**
 * Core ParseMoney: an amount in BTC with at most 8 decimals and at most 10
 * whole digits, no sign, no exponent, no inner whitespace, inside MoneyRange.
 * Returns satoshis, or null when Core would return std::nullopt.
 */
export function parseMoney(money: string): bigint | null {
  if (money.includes("\0")) return null;
  // TrimString: strip the C-locale whitespace from both ends.
  let start = 0;
  let end = money.length;
  while (start < end && isSpace(money[start])) start++;
  while (end > start && isSpace(money[end - 1])) end--;
  const str = money.slice(start, end);
  if (str.length === 0) return null;

  let whole = "";
  let units = 0n;
  let p = 0;
  for (; p < str.length; p++) {
    if (str[p] === ".") {
      p++;
      let mult = COIN / 10n;
      while (isDigit(str[p]) && mult > 0n) {
        units += mult * BigInt(str.charCodeAt(p) - 48);
        p++;
        mult /= 10n;
      }
      break;
    }
    if (!isDigit(str[p])) return null; // whitespace, sign, junk
    whole += str[p];
  }
  if (p < str.length) return null; // a second dot, a 9th decimal, trailing junk
  if (whole.length > 10) return null; // guard against 63-bit overflow
  const value = BigInt(whole.length > 0 ? whole : "0") * COIN + units;
  if (value < 0n || value > MAX_MONEY) return null; // MoneyRange
  return value;
}

/**
 * Resolve `-fallbackfee` the way CWallet::Create does. `raw` is the string the
 * user gave (CLI `--fallbackfee=<v>` or config `fallbackfee=<v>`; a bare
 * `--fallbackfee` is ""), or undefined when unset (Core default 0 = disabled).
 * Throws with Core's init error for an amount ParseMoney refuses; returns the
 * rate in sat/kvB plus Core's warning when it exceeds HIGH_TX_FEE_PER_KB.
 */
export function parseFallbackFee(raw: string | undefined): { satKvB: number; warning?: string } {
  if (raw === undefined) return { satKvB: 0 };
  const amount = parseMoney(raw);
  if (amount === null) {
    throw new Error(`Invalid amount for -fallbackfee=<amount>: '${raw}'`);
  }
  const satKvB = Number(amount);
  if (satKvB > HIGH_TX_FEE_PER_KB) {
    return {
      satKvB,
      warning:
        "-fallbackfee is set very high! This is the transaction fee you may pay when fee estimates are not available.",
    };
  }
  return { satKvB };
}
