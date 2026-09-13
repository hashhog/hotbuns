/**
 * Per-file process isolation for `bun test` (the v1.0.2 unit gate).
 *
 * Bun loads this preload once per test file in a SINGLE process, with
 * argv = [bun, <that file>]. The first invocation in a process discovers
 * the suite, runs each file in a child (`HOTBUNS_UNIT_CHILD=1`), prints a
 * bun-style summary, and exits so leaks / port clashes / AddrMan state
 * cannot accumulate. Children return immediately from this preload.
 *
 * In-process single file: HOTBUNS_UNIT_CHILD=1 bun test ./src/foo.test.ts
 */
import { Glob } from "bun";
import { join } from "node:path";

const CHILD = "HOTBUNS_UNIT_CHILD";
const FILE_TIMEOUT_MS = 60_000;
const g = globalThis as unknown as { __hotbunsUnitIsolate?: boolean };

function ignored(rel: string, patterns: string[]): boolean {
  const norm = rel.replaceAll("\\", "/");
  for (const p of patterns) {
    const suffix = p.replace(/^\*\*\//, "");
    if (norm === suffix || norm.endsWith("/" + suffix)) return true;
  }
  return false;
}

async function discoverTestFiles(root: string, patterns: string[]): Promise<string[]> {
  const glob = new Glob("**/*.{test,spec}.{ts,tsx,js,jsx}");
  const files: string[] = [];
  for await (const match of glob.scan({ cwd: root, onlyFiles: true })) {
    const rel = match.replaceAll("\\", "/");
    if (rel.startsWith("node_modules/") || rel.includes("/node_modules/")) continue;
    if (rel.startsWith("dist/") || rel.includes("/dist/")) continue;
    if (rel.startsWith("scripts/")) continue;
    if (ignored(rel, patterns)) continue;
    files.push(rel);
  }
  files.sort();
  return files;
}

function parseSummary(text: string): { pass: number; fail: number; skip: number; todo: number } {
  const strip = text.replace(/\x1b\[[0-9;]*m/g, "");
  const num = (re: RegExp) => {
    const ms = [...strip.matchAll(re)];
    if (ms.length === 0) return 0;
    return Number(ms[ms.length - 1]![1]);
  };
  return {
    pass: num(/^[ \t]*([0-9]+) pass[ \t]*$/gm),
    fail: num(/^[ \t]*([0-9]+) fail[ \t]*$/gm),
    skip: num(/^[ \t]*([0-9]+) skip[ \t]*$/gm),
    todo: num(/^[ \t]*([0-9]+) todo[ \t]*$/gm),
  };
}

async function isolate(): Promise<void> {
  if (process.env[CHILD] === "1") return;
  if (g.__hotbunsUnitIsolate) return;
  g.__hotbunsUnitIsolate = true;

  const root = join(import.meta.dir, "..");
  const bunfigText = await Bun.file(join(root, "bunfig.toml")).text();
  const patterns = [...bunfigText.matchAll(/"(\*\*\/[^"]+\.test\.ts)"/g)].map(
    (m) => m[1]!,
  );

  const files = await discoverTestFiles(root, patterns);
  if (files.length === 0) {
    console.error("unit-isolate: discovered 0 test files");
    process.exit(1);
  }

  const bunExe = process.execPath;
  const t0 = Date.now();
  let pass = 0;
  let fail = 0;
  let skip = 0;
  let todo = 0;
  let filesFailed = 0;

  for (const rel of files) {
    const proc = Bun.spawn([bunExe, "test", "./" + rel], {
      cwd: root,
      env: { ...process.env, [CHILD]: "1" },
      stdout: "pipe",
      stderr: "pipe",
      timeout: FILE_TIMEOUT_MS,
    });
    const [stdout, stderr, exit] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    const text = stdout + stderr;
    process.stdout.write(text);
    const s = parseSummary(text);
    pass += s.pass;
    fail += s.fail;
    skip += s.skip;
    todo += s.todo;
    if (exit !== 0 || s.fail > 0) {
      filesFailed++;
      if (s.pass === 0 && s.fail === 0) {
        fail += 1;
        console.error(
          `unit-isolate: ${rel} exited ${exit} with no summary (timeout or crash)`,
        );
      }
    }
  }

  const secs = ((Date.now() - t0) / 1000).toFixed(2);
  const ran = pass + fail + skip + todo;
  console.log("");
  console.log(` ${pass} pass`);
  console.log(` ${fail} fail`);
  console.log(` ${skip} skip`);
  console.log(` ${todo} todo`);
  console.log(`Ran ${ran} tests across ${files.length} files. [${secs}s]`);
  process.exit(fail > 0 || filesFailed > 0 ? 1 : 0);
}

await isolate();
