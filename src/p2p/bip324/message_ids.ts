/**
 * BIP324 short message ID mapping.
 *
 * V2 transport uses 1-byte short IDs for common message types instead of
 * the 12-byte ASCII command names used in V1.
 *
 * Reference: Bitcoin Core src/net.cpp V2_MESSAGE_IDS
 */

/**
 * Short message IDs as defined in BIP324.
 *
 * Index 0 is reserved (means the message type follows as 12-byte ASCII).
 * Indices 1-32 are assigned to common message types.
 */
export const V2_MESSAGE_IDS: readonly string[] = [
  "",            // 0: 12-byte encoding follows
  "addr",        // 1
  "block",       // 2
  "blocktxn",    // 3
  "cmpctblock",  // 4
  "feefilter",   // 5
  "filteradd",   // 6
  "filterclear", // 7
  "filterload",  // 8
  "getblocks",   // 9
  "getblocktxn", // 10
  "getdata",     // 11
  "getheaders",  // 12
  "headers",     // 13
  "inv",         // 14
  "mempool",     // 15
  "merkleblock", // 16
  "notfound",    // 17
  "ping",        // 18
  "pong",        // 19
  "sendcmpct",   // 20
  "tx",          // 21
  "getcfilters", // 22
  "cfilter",     // 23
  "getcfheaders",// 24
  "cfheaders",   // 25
  "getcfcheckpt",// 26
  "cfcheckpt",   // 27
  "addrv2",      // 28
  "",            // 29: unassigned
  "",            // 30: unassigned
  "",            // 31: unassigned
  "",            // 32: unassigned
] as const;

/** Map from message type to short ID */
const messageTypeToId = new Map<string, number>();

// Build the reverse mapping
for (let i = 1; i < V2_MESSAGE_IDS.length; i++) {
  const msgType = V2_MESSAGE_IDS[i];
  if (msgType !== "") {
    messageTypeToId.set(msgType, i);
  }
}

/** Maximum length of a message type string */
export const MESSAGE_TYPE_SIZE = 12;

/**
 * Encode a message type for V2 transport.
 *
 * If the message type has a short ID, returns a single byte.
 * Otherwise, returns 13 bytes: 0x00 prefix + 12-byte null-padded ASCII.
 *
 * @param msgType - Message type string
 * @returns Encoded message type
 */
export function encodeMessageType(msgType: string): Buffer {
  // Check for short ID
  const shortId = messageTypeToId.get(msgType);
  if (shortId !== undefined) {
    return Buffer.from([shortId]);
  }

  // Use long encoding: 0x00 + 12-byte null-padded ASCII
  if (msgType.length > MESSAGE_TYPE_SIZE) {
    throw new Error(`Message type too long: ${msgType}`);
  }

  const buf = Buffer.alloc(1 + MESSAGE_TYPE_SIZE, 0);
  buf[0] = 0x00;
  buf.write(msgType, 1, "ascii");
  return buf;
}

/**
 * Decode a message type from V2 transport packet contents.
 *
 * @param contents - Packet contents (first byte is message type indicator)
 * @returns { msgType, remaining } where remaining is the payload
 */
export function decodeMessageType(contents: Buffer): {
  msgType: string | null;
  remaining: Buffer;
} {
  if (contents.length === 0) {
    return { msgType: null, remaining: Buffer.alloc(0) };
  }

  const firstByte = contents[0];

  if (firstByte !== 0) {
    // Short encoding
    if (firstByte >= V2_MESSAGE_IDS.length) {
      // Unknown short ID
      return { msgType: null, remaining: contents.subarray(1) };
    }

    const msgType = V2_MESSAGE_IDS[firstByte];
    if (msgType === "") {
      // Unassigned short ID
      return { msgType: null, remaining: contents.subarray(1) };
    }

    return { msgType, remaining: contents.subarray(1) };
  }

  // Long encoding: 12-byte ASCII follows
  if (contents.length < 1 + MESSAGE_TYPE_SIZE) {
    return { msgType: null, remaining: Buffer.alloc(0) };
  }

  // Extract message type (up to first null byte)
  const typeBytes = contents.subarray(1, 1 + MESSAGE_TYPE_SIZE);
  let msgTypeLen = 0;
  while (msgTypeLen < MESSAGE_TYPE_SIZE && typeBytes[msgTypeLen] !== 0) {
    // Verify ASCII range
    const c = typeBytes[msgTypeLen];
    if (c < 0x20 || c > 0x7f) {
      return { msgType: null, remaining: contents.subarray(1 + MESSAGE_TYPE_SIZE) };
    }
    msgTypeLen++;
  }

  // Verify remaining bytes are null
  for (let i = msgTypeLen; i < MESSAGE_TYPE_SIZE; i++) {
    if (typeBytes[i] !== 0) {
      return { msgType: null, remaining: contents.subarray(1 + MESSAGE_TYPE_SIZE) };
    }
  }

  const msgType = typeBytes.toString("ascii", 0, msgTypeLen);
  return { msgType, remaining: contents.subarray(1 + MESSAGE_TYPE_SIZE) };
}

/**
 * Check if a message type has a short ID.
 *
 * @param msgType - Message type string
 * @returns true if the message type has a 1-byte short ID
 */
export function hasShortId(msgType: string): boolean {
  return messageTypeToId.has(msgType);
}

/**
 * Get the short ID for a message type, if it exists.
 *
 * @param msgType - Message type string
 * @returns Short ID (1-32) or undefined
 */
export function getShortId(msgType: string): number | undefined {
  return messageTypeToId.get(msgType);
}

/**
 * Get the message type for a short ID.
 *
 * @param shortId - Short ID (1-32)
 * @returns Message type string or null if invalid/unassigned
 */
export function getMessageType(shortId: number): string | null {
  if (shortId <= 0 || shortId >= V2_MESSAGE_IDS.length) {
    return null;
  }
  const msgType = V2_MESSAGE_IDS[shortId];
  return msgType !== "" ? msgType : null;
}
