/**
 * Ban manager for persistent peer banning.
 *
 * Manages a list of banned IP addresses/subnets with expiration times.
 * Persists to banlist.json using Bun.write().
 *
 * Reference: Bitcoin Core's banman.cpp
 */

/** Default ban duration: 24 hours in seconds. */
export const DEFAULT_BAN_TIME = 24 * 60 * 60;

/** A single ban entry. */
export interface BanEntry {
  /** The IP address or subnet that is banned. */
  address: string;
  /** Unix timestamp when the ban was created. */
  banCreated: number;
  /** Unix timestamp when the ban expires. */
  banUntil: number;
  /** Reason for the ban. */
  reason: string;
}

/** Serialized format for the banlist file. */
interface BanlistFile {
  version: number;
  bans: BanEntry[];
}

/**
 * Manages banned peers with persistent storage.
 *
 * Peers are banned by IP address (or subnet in future versions).
 * Bans are persisted to disk and loaded on startup.
 */
export class BanManager {
  private banned: Map<string, BanEntry>;
  private datadir: string;
  private isDirty: boolean;

  constructor(datadir: string) {
    this.datadir = datadir;
    this.banned = new Map();
    this.isDirty = false;
  }

  /**
   * Load the ban list from disk.
   */
  async load(): Promise<void> {
    const path = `${this.datadir}/banlist.json`;
    try {
      const file = Bun.file(path);
      if (await file.exists()) {
        const content = await file.text();
        const data = JSON.parse(content) as BanlistFile;

        if (data.version !== 1) {
          console.log(`Unknown banlist version: ${data.version}, recreating`);
          this.banned = new Map();
          return;
        }

        // Load bans and sweep expired ones
        const now = Math.floor(Date.now() / 1000);
        for (const entry of data.bans) {
          if (now < entry.banUntil) {
            this.banned.set(entry.address, entry);
          }
        }

        console.log(`Loaded ${this.banned.size} banned addresses`);
      }
    } catch (error) {
      console.log("No banlist found or error loading, starting fresh");
      this.banned = new Map();
    }
  }

  /**
   * Save the ban list to disk.
   */
  async save(): Promise<void> {
    if (!this.isDirty) {
      return;
    }

    const path = `${this.datadir}/banlist.json`;
    const data: BanlistFile = {
      version: 1,
      bans: Array.from(this.banned.values()),
    };

    try {
      await Bun.write(path, JSON.stringify(data, null, 2));
      this.isDirty = false;
    } catch (error) {
      console.error("Failed to save banlist:", error);
    }
  }

  /**
   * Check if an IP address is banned.
   *
   * @param address - IP address to check
   * @returns true if banned and not expired
   */
  isBanned(address: string): boolean {
    const entry = this.banned.get(address);
    if (!entry) {
      return false;
    }

    const now = Math.floor(Date.now() / 1000);
    if (now >= entry.banUntil) {
      // Ban expired, remove it
      this.banned.delete(address);
      this.isDirty = true;
      return false;
    }

    return true;
  }

  /**
   * Ban an IP address.
   *
   * @param address - IP address to ban
   * @param banTime - Ban duration in seconds (default: 24 hours)
   * @param reason - Reason for the ban
   * @param absolute - If true, banTime is an absolute Unix timestamp
   */
  ban(
    address: string,
    banTime: number = DEFAULT_BAN_TIME,
    reason: string = "",
    absolute: boolean = false
  ): void {
    const now = Math.floor(Date.now() / 1000);
    const banUntil = absolute ? banTime : now + banTime;

    const entry: BanEntry = {
      address,
      banCreated: now,
      banUntil,
      reason,
    };

    // Only update if the new ban is longer
    const existing = this.banned.get(address);
    if (existing && existing.banUntil >= banUntil) {
      return;
    }

    this.banned.set(address, entry);
    this.isDirty = true;

    // Save immediately (following Bitcoin Core's DumpBanlist pattern)
    this.save().catch((err) => console.error("Failed to save banlist:", err));
  }

  /**
   * Remove a ban for an IP address.
   *
   * @param address - IP address to unban
   * @returns true if the address was banned and is now unbanned
   */
  unban(address: string): boolean {
    if (!this.banned.has(address)) {
      return false;
    }

    this.banned.delete(address);
    this.isDirty = true;

    // Save immediately
    this.save().catch((err) => console.error("Failed to save banlist:", err));
    return true;
  }

  /**
   * Clear all bans.
   */
  clearBanned(): void {
    this.banned.clear();
    this.isDirty = true;
    this.save().catch((err) => console.error("Failed to save banlist:", err));
  }

  /**
   * Get all current bans.
   *
   * @returns Array of ban entries (unexpired)
   */
  getBanned(): BanEntry[] {
    const now = Math.floor(Date.now() / 1000);
    const result: BanEntry[] = [];

    for (const [address, entry] of this.banned) {
      if (now < entry.banUntil) {
        result.push(entry);
      } else {
        // Expired, clean up
        this.banned.delete(address);
        this.isDirty = true;
      }
    }

    return result;
  }

  /**
   * Sweep expired bans from the list.
   */
  sweepBanned(): void {
    const now = Math.floor(Date.now() / 1000);
    let removed = 0;

    for (const [address, entry] of this.banned) {
      if (now >= entry.banUntil) {
        this.banned.delete(address);
        removed++;
      }
    }

    if (removed > 0) {
      this.isDirty = true;
      console.log(`Removed ${removed} expired bans`);
    }
  }
}
