/**
 * Growable receive buffer with amortized O(1) appends.
 *
 * Both transports used to rebuild their receive buffer on every socket read
 * (`allocUnsafe(old + new)` + copy in Peer.onData, `Buffer.concat` plus a
 * `Buffer.from` copy of the remainder per packet in V2Transport). A peer that
 * drips one 4 MB message a few hundred bytes at a time then costs O(n^2)
 * memcpy: about 8 GB of copying for a single 4 MB message in 1,000-byte reads.
 *
 * Core appends in place and grows the vector geometrically
 * (net.cpp V1Transport::readData resizes vRecv to
 * min(nMessageSize, nDataPos + nCopy + 256 KiB); std::vector reallocates
 * geometrically). This class does the same: appends land in spare capacity,
 * and when capacity runs out the live bytes move once into a buffer at least
 * twice their size, so the total copied for n received bytes is O(n).
 *
 * Aliasing invariant: callers hand out subarray views of {@link view} (a v1
 * payload being parsed across macrotasks, and deserialized messages may keep
 * views of it). So no byte is ever written twice in one backing store:
 * appends only write past `end`, growth and compaction move the live bytes
 * into a NEW store and leave the old one untouched, and draining to empty
 * drops the store rather than rewinding `end`.
 */
const EMPTY = Buffer.alloc(0);
/** Stores at or below this size are never shrunk on consume. */
const SHRINK_MIN_STORE = 256 * 1024;

export class RecvBuffer {
  private store: Buffer = EMPTY;
  private start = 0;
  private end = 0;

  /** Bytes received and not yet consumed. */
  get length(): number {
    return this.end - this.start;
  }

  /** The unconsumed bytes, as a view (no copy). */
  view(): Buffer {
    return this.store.subarray(this.start, this.end);
  }

  /** Copy `data` onto the end. Amortized O(data.length). */
  append(data: Uint8Array): void {
    const n = data.length;
    if (n === 0) return;
    if (this.end + n <= this.store.length) {
      this.store.set(data, this.end);
      this.end += n;
      return;
    }
    const live = this.end - this.start;
    const need = live + n;
    const grown = Buffer.allocUnsafe(Math.max(need, 2 * live));
    if (live > 0) this.store.copy(grown, 0, this.start, this.end);
    grown.set(data, live);
    this.store = grown;
    this.start = 0;
    this.end = need;
  }

  /** Drop the first `n` unconsumed bytes. */
  consume(n: number): void {
    if (n < 0 || n > this.length) {
      throw new RangeError(`RecvBuffer.consume(${n}) with ${this.length} bytes buffered`);
    }
    this.start += n;
    if (this.start === this.end) {
      this.clear();
    } else if (this.store.length > SHRINK_MIN_STORE && 4 * this.length < this.store.length) {
      // A small tail left behind a large message: move it to its own store so
      // a peer that always keeps a partial message buffered does not pin the
      // large one. Copies at most a quarter of the store, and only after
      // `n` bytes were consumed, so appends stay amortized O(1).
      const tail = Buffer.allocUnsafe(this.length);
      this.store.copy(tail, 0, this.start, this.end);
      this.store = tail;
      this.start = 0;
      this.end = tail.length;
    }
  }

  /** Return the unconsumed bytes as a view and empty the buffer. */
  takeAll(): Buffer {
    const out = this.view();
    this.clear();
    return out;
  }

  /** Empty the buffer and release its store. */
  clear(): void {
    this.store = EMPTY;
    this.start = 0;
    this.end = 0;
  }
}
