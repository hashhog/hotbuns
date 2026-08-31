import { existsSync } from "fs";

/**
 * Locate a Bitcoin Core test-vector file.
 *
 * The vector suites used to hard-code absolute paths to a developer laptop
 * ("/home/max/hashhog/bitcoin/..." and "/home/max/hashhog/ouroboros/bitcoin/..."),
 * neither of which exists on the build host, so they threw in readFileSync
 * before checking a single vector. Found 2026-08-30 while fixing the same class
 * of breakage in clearbit, camlcoin, nimrod and blockbrew.
 *
 * Search several depths so the lookup works whether the cwd is the repo root,
 * this submodule, or a subdirectory, and throw naming every path tried — a
 * vector harness that cannot find its vectors must never look like a pass.
 */
export function findVectorFile(name: string): string {
  const prefixes = ["", "../", "../../", "../../../", "../../../../"];
  const rels = ["bitcoin-core/src/test/data/", "resources/"];
  const tried: string[] = [];
  for (const p of prefixes) {
    for (const r of rels) {
      const c = `${p}${r}${name}`;
      tried.push(c);
      if (existsSync(c)) return c;
    }
  }
  throw new Error(
    `FATAL: could not find test vectors '${name}'. Tried:\n  ` + tried.join("\n  "),
  );
}
