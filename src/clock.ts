/**
 * Process-wide clock with a regtest-only mock override.
 *
 * Mirrors Bitcoin Core's GetTime()/SetMockTime() (util/time.cpp): when a
 * non-zero mock time is set, every caller of nowSeconds()/nowMillis() sees it
 * instead of the wall clock; 0 returns to the system time. Only the RPC
 * `setmocktime` (regtest) sets it.
 */

let mockTimeSeconds = 0;

export function setMockTime(seconds: number): void {
  mockTimeSeconds = seconds;
}

export function getMockTime(): number {
  return mockTimeSeconds;
}

export function nowSeconds(): number {
  return mockTimeSeconds !== 0 ? mockTimeSeconds : Math.floor(Date.now() / 1000);
}

export function nowMillis(): number {
  return mockTimeSeconds !== 0 ? mockTimeSeconds * 1000 : Date.now();
}
