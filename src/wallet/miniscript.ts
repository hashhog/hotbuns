/**
 * Miniscript: A structured representation of Bitcoin Script
 *
 * Miniscript is a language for writing Bitcoin Scripts in a structured way
 * that enables analysis, composition, and generic signing. It provides:
 *
 * - Type system: Each node has a type (B, V, K, W) and properties (z, o, n, d, u, f, e, m, s, k, x)
 * - Script compilation: Convert miniscript AST to Bitcoin Script
 * - Satisfaction: Compute minimal witness given available keys/preimages/timelocks
 * - Analysis: Compute max witness size, required keys, timelock conflicts
 *
 * References:
 * - https://bitcoin.sipa.be/miniscript/
 * - Bitcoin Core: /src/script/miniscript.cpp
 */

import { sha256Hash, hash256, hash160 } from "../crypto/primitives.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { Opcode } from "../script/interpreter.js";

// =============================================================================
// Constants
// =============================================================================

/** Maximum script size for P2WSH */
const MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;

/** Maximum script size for Tapscript */
const MAX_TAPSCRIPT_SIZE = 10000;

/** Maximum number of keys in CHECKMULTISIG (P2WSH) */
const MAX_MULTISIG_KEYS = 20;

/** Maximum number of keys in CHECKSIGADD (Tapscript) */
const MAX_MULTI_A_KEYS = 999;

/** Maximum stack size allowed */
const MAX_STACK_SIZE = 1000;

/** Maximum sigops in a P2WSH script */
const MAX_OPS_PER_SCRIPT = 201;

/** Sequence locktime type flag for CSV */
const SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22;

/** Locktime threshold for CLTV (block height vs Unix timestamp) */
const LOCKTIME_THRESHOLD = 500000000;

// =============================================================================
// Miniscript Context
// =============================================================================

/**
 * Context in which a miniscript is used.
 * Affects script compilation and validation rules.
 */
export enum MiniscriptContext {
  /** P2WSH context - uses CHECKMULTISIG, max 20 keys */
  P2WSH = "p2wsh",
  /** Tapscript context - uses CHECKSIGADD, max 999 keys */
  TAPSCRIPT = "tapscript",
}

// =============================================================================
// Type System
// =============================================================================

/**
 * Miniscript base types.
 * Each expression has exactly one base type.
 */
export enum BaseType {
  /** Base type - can be used at top level or in most combiners */
  B = "B",
  /** Verify type - leaves nothing on stack (used in and_v) */
  V = "V",
  /** Key type - expects a key on the stack */
  K = "K",
  /** Wrapped type - used in threshold operations */
  W = "W",
}

/**
 * Miniscript type properties.
 * A set of properties that describe satisfaction/dissatisfaction behavior.
 */
export interface TypeProperties {
  /** z - Zero-arg: Satisfaction and dissatisfaction have empty stack (0 elements) */
  z: boolean;
  /** o - One-arg: Satisfaction and dissatisfaction have 1 stack element */
  o: boolean;
  /** n - Nonzero: Satisfaction must have non-zero top element */
  n: boolean;
  /** d - Dissatisfiable: Can be dissatisfied without a signature */
  d: boolean;
  /** u - Unit: Satisfaction leaves a 1 on the stack */
  u: boolean;
  /** f - Forced: Cannot be dissatisfied (only happens for type V) */
  f: boolean;
  /** e - Expression: Has both satisfaction and dissatisfaction */
  e: boolean;
  /** m - Nonmalleable: Can always be satisfied non-malleably */
  m: boolean;
  /** s - Safe: Satisfaction requires a signature */
  s: boolean;
  /** k - No timelock mixing: No mixing of height and time timelocks */
  k: boolean;
  /** x - Expensive verify: Requires OP_VERIFY (adds cost) */
  x: boolean;
  /** g - Contains relative time timelock (CSV with time flag) */
  g: boolean;
  /** h - Contains relative height timelock (CSV without time flag) */
  h: boolean;
  /** i - Contains absolute time timelock (CLTV with time) */
  i: boolean;
  /** j - Contains absolute height timelock (CLTV with height) */
  j: boolean;
}

/**
 * Full miniscript type including base type and properties.
 */
export interface MiniscriptType {
  base: BaseType;
  props: TypeProperties;
}

/**
 * Create default (empty) type properties.
 */
function emptyProps(): TypeProperties {
  return {
    z: false,
    o: false,
    n: false,
    d: false,
    u: false,
    f: false,
    e: false,
    m: false,
    s: false,
    k: true, // k is true by default (no timelock conflicts)
    x: false,
    g: false,
    h: false,
    i: false,
    j: false,
  };
}

/**
 * Create a type with specified properties.
 */
function makeType(
  base: BaseType,
  overrides: Partial<TypeProperties>
): MiniscriptType {
  return {
    base,
    props: { ...emptyProps(), ...overrides },
  };
}

/**
 * Check if two types are compatible for timelock mixing.
 */
function checkTimeLocksMix(props: TypeProperties): boolean {
  // Check for height/time mixing
  // g, h are relative (CSV); i, j are absolute (CLTV)
  // g=time, h=height for relative; i=time, j=height for absolute
  const hasRelTime = props.g;
  const hasRelHeight = props.h;
  const hasAbsTime = props.i;
  const hasAbsHeight = props.j;

  // Cannot mix time and height timelocks
  const hasTime = hasRelTime || hasAbsTime;
  const hasHeight = hasRelHeight || hasAbsHeight;

  return !(hasTime && hasHeight);
}

/**
 * Validate type consistency.
 */
function validateType(type: MiniscriptType): boolean {
  const { base, props } = type;

  // z and o are mutually exclusive
  if (props.z && props.o) return false;

  // n requires not z
  if (props.n && props.z) return false;

  // n requires not W
  if (props.n && base === BaseType.W) return false;

  // V requires not d
  if (base === BaseType.V && props.d) return false;

  // K requires u
  if (base === BaseType.K && !props.u) return false;

  // V requires not u
  if (base === BaseType.V && props.u) return false;

  // e requires not f
  if (props.e && props.f) return false;

  // e requires d
  if (props.e && !props.d) return false;

  // V requires not e
  if (base === BaseType.V && props.e) return false;

  // d requires not f
  if (props.d && props.f) return false;

  // V requires f
  if (base === BaseType.V && !props.f) return false;

  // K requires s
  if (base === BaseType.K && !props.s) return false;

  // z requires m (consensus requirement for zero-arg expressions)
  if (props.z && !props.m) return false;

  // k requires no timelock mixing
  if (props.k && !checkTimeLocksMix(props)) return false;

  return true;
}

// =============================================================================
// AST Node Types
// =============================================================================

/**
 * Miniscript AST node - discriminated union of all fragment types.
 */
export type MiniscriptNode =
  | JustZeroNode
  | JustOneNode
  | PkKNode
  | PkHNode
  | OlderNode
  | AfterNode
  | Sha256Node
  | Hash256Node
  | Ripemd160Node
  | Hash160Node
  | AndVNode
  | AndBNode
  | OrBNode
  | OrCNode
  | OrDNode
  | OrINode
  | AndOrNode
  | ThreshNode
  | MultiNode
  | MultiANode
  // Wrappers
  | WrapANode
  | WrapSNode
  | WrapCNode
  | WrapDNode
  | WrapVNode
  | WrapJNode
  | WrapNNode;

/** just_0: OP_0 */
export interface JustZeroNode {
  type: "just_0";
}

/** just_1: OP_1 */
export interface JustOneNode {
  type: "just_1";
}

/** pk_k(KEY): <key> */
export interface PkKNode {
  type: "pk_k";
  key: Buffer;
}

/** pk_h(KEY): OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY */
export interface PkHNode {
  type: "pk_h";
  keyHash: Buffer;
  /** Original key for satisfaction, if known */
  key?: Buffer;
}

/** older(N): <n> OP_CHECKSEQUENCEVERIFY */
export interface OlderNode {
  type: "older";
  sequence: number;
}

/** after(N): <n> OP_CHECKLOCKTIMEVERIFY */
export interface AfterNode {
  type: "after";
  locktime: number;
}

/** sha256(H): OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL */
export interface Sha256Node {
  type: "sha256";
  hash: Buffer;
}

/** hash256(H): OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL */
export interface Hash256Node {
  type: "hash256";
  hash: Buffer;
}

/** ripemd160(H): OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL */
export interface Ripemd160Node {
  type: "ripemd160";
  hash: Buffer;
}

/** hash160(H): OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL */
export interface Hash160Node {
  type: "hash160";
  hash: Buffer;
}

/** and_v(X,Y): [X] [Y] */
export interface AndVNode {
  type: "and_v";
  left: MiniscriptNode;
  right: MiniscriptNode;
}

/** and_b(X,Y): [X] [Y] OP_BOOLAND */
export interface AndBNode {
  type: "and_b";
  left: MiniscriptNode;
  right: MiniscriptNode;
}

/** or_b(X,Y): [X] [Y] OP_BOOLOR */
export interface OrBNode {
  type: "or_b";
  left: MiniscriptNode;
  right: MiniscriptNode;
}

/** or_c(X,Y): [X] OP_NOTIF [Y] OP_ENDIF */
export interface OrCNode {
  type: "or_c";
  left: MiniscriptNode;
  right: MiniscriptNode;
}

/** or_d(X,Y): [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF */
export interface OrDNode {
  type: "or_d";
  left: MiniscriptNode;
  right: MiniscriptNode;
}

/** or_i(X,Y): OP_IF [X] OP_ELSE [Y] OP_ENDIF */
export interface OrINode {
  type: "or_i";
  left: MiniscriptNode;
  right: MiniscriptNode;
}

/** andor(X,Y,Z): [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF */
export interface AndOrNode {
  type: "andor";
  cond: MiniscriptNode;
  ifTrue: MiniscriptNode;
  ifFalse: MiniscriptNode;
}

/** thresh(k,X,Y,...): [X1] ([Xn] OP_ADD)* [k] OP_EQUAL */
export interface ThreshNode {
  type: "thresh";
  threshold: number;
  subs: MiniscriptNode[];
}

/** multi(k,KEY,...): [k] [key_n]* [n] OP_CHECKMULTISIG */
export interface MultiNode {
  type: "multi";
  threshold: number;
  keys: Buffer[];
}

/** multi_a(k,KEY,...): [key_0] OP_CHECKSIG ([key_n] OP_CHECKSIGADD)* [k] OP_NUMEQUAL */
export interface MultiANode {
  type: "multi_a";
  threshold: number;
  keys: Buffer[];
}

/** a:X - WRAP_A: OP_TOALTSTACK [X] OP_FROMALTSTACK */
export interface WrapANode {
  type: "wrap_a";
  inner: MiniscriptNode;
}

/** s:X - WRAP_S: OP_SWAP [X] */
export interface WrapSNode {
  type: "wrap_s";
  inner: MiniscriptNode;
}

/** c:X - WRAP_C: [X] OP_CHECKSIG */
export interface WrapCNode {
  type: "wrap_c";
  inner: MiniscriptNode;
}

/** d:X - WRAP_D: OP_DUP OP_IF [X] OP_ENDIF */
export interface WrapDNode {
  type: "wrap_d";
  inner: MiniscriptNode;
}

/** v:X - WRAP_V: [X] OP_VERIFY (or -VERIFY suffix) */
export interface WrapVNode {
  type: "wrap_v";
  inner: MiniscriptNode;
}

/** j:X - WRAP_J: OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF */
export interface WrapJNode {
  type: "wrap_j";
  inner: MiniscriptNode;
}

/** n:X - WRAP_N: [X] OP_0NOTEQUAL */
export interface WrapNNode {
  type: "wrap_n";
  inner: MiniscriptNode;
}

// =============================================================================
// Type Computation
// =============================================================================

/**
 * Compute the type of a miniscript node.
 */
export function computeType(
  node: MiniscriptNode,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): MiniscriptType {
  switch (node.type) {
    case "just_0":
      // 0: type Bzudemsx
      return makeType(BaseType.B, {
        z: true,
        u: true,
        d: true,
        e: false,
        m: true,
        s: false,
        x: false,
      });

    case "just_1":
      // 1: type Bzufmsx
      return makeType(BaseType.B, {
        z: true,
        u: true,
        f: true,
        m: true,
        s: false,
        x: false,
      });

    case "pk_k":
      // pk_k(KEY): type Konudemsxk
      return makeType(BaseType.K, {
        o: true,
        n: true,
        u: true,
        d: true,
        e: true,
        m: true,
        s: true,
        x: false,
      });

    case "pk_h":
      // pk_h(KEY): type Knudemsxk
      return makeType(BaseType.K, {
        n: true,
        u: true,
        d: true,
        e: true,
        m: true,
        s: true,
        x: false,
      });

    case "older": {
      // older(n): type Bzfmxk, plus g or h for timelock type
      const isTime = (node.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0;
      return makeType(BaseType.B, {
        z: true,
        f: true,
        m: true,
        x: false,
        g: isTime,
        h: !isTime,
      });
    }

    case "after": {
      // after(n): type Bzfmxk, plus i or j for timelock type
      const isTime = node.locktime >= LOCKTIME_THRESHOLD;
      return makeType(BaseType.B, {
        z: true,
        f: true,
        m: true,
        x: false,
        i: isTime,
        j: !isTime,
      });
    }

    case "sha256":
    case "hash256":
    case "ripemd160":
    case "hash160":
      // hash functions: type Bonudmk
      return makeType(BaseType.B, {
        o: true,
        n: true,
        u: true,
        d: true,
        m: true,
      });

    case "and_v": {
      const leftType = computeType(node.left, ctx);
      const rightType = computeType(node.right, ctx);
      const lp = leftType.props;
      const rp = rightType.props;

      // and_v(X,Y): V,X -> B or V,Y -> B or K,Y
      // type: B = V_x * (B_y | V_y | K_y)
      let base: BaseType;
      if (leftType.base === BaseType.V) {
        base = rightType.base;
      } else {
        throw new Error("and_v left child must be type V");
      }

      return makeType(base, {
        z: lp.z && rp.z,
        o: (lp.o && rp.z) || (lp.z && rp.o),
        n: lp.n || (lp.z && rp.n),
        u: rp.u,
        d: false, // V cannot be dissatisfied
        f: rp.f || lp.s,
        e: false,
        m: lp.m && rp.m,
        s: lp.s || rp.s,
        x: rp.x,
        g: lp.g || rp.g,
        h: lp.h || rp.h,
        i: lp.i || rp.i,
        j: lp.j || rp.j,
        k: lp.k && rp.k && checkTimeLocksMix({ ...emptyProps(), g: lp.g || rp.g, h: lp.h || rp.h, i: lp.i || rp.i, j: lp.j || rp.j }),
      });
    }

    case "and_b": {
      const leftType = computeType(node.left, ctx);
      const rightType = computeType(node.right, ctx);
      const lp = leftType.props;
      const rp = rightType.props;

      // and_b(X,Y): B,W -> B
      if (leftType.base !== BaseType.B || rightType.base !== BaseType.W) {
        throw new Error("and_b requires B and W types");
      }

      return makeType(BaseType.B, {
        z: lp.z && rp.z,
        o: (lp.o && rp.z) || (lp.z && rp.o),
        n: lp.n || (lp.z && rp.n),
        u: true,
        d: lp.d && rp.d,
        f: lp.f && rp.f,
        e: lp.e && rp.e && (lp.s || rp.s),
        m: lp.m && rp.m,
        s: lp.s || rp.s,
        x: lp.x || rp.x,
        g: lp.g || rp.g,
        h: lp.h || rp.h,
        i: lp.i || rp.i,
        j: lp.j || rp.j,
        k: lp.k && rp.k && checkTimeLocksMix({ ...emptyProps(), g: lp.g || rp.g, h: lp.h || rp.h, i: lp.i || rp.i, j: lp.j || rp.j }),
      });
    }

    case "or_b": {
      const leftType = computeType(node.left, ctx);
      const rightType = computeType(node.right, ctx);
      const lp = leftType.props;
      const rp = rightType.props;

      // or_b(X,Y): Bd,Wd -> B
      if (leftType.base !== BaseType.B || !lp.d) {
        throw new Error("or_b left must be Bd");
      }
      if (rightType.base !== BaseType.W || !rp.d) {
        throw new Error("or_b right must be Wd");
      }

      return makeType(BaseType.B, {
        z: lp.z && rp.z,
        o: (lp.o && rp.z) || (lp.z && rp.o),
        n: false,
        u: true,
        d: true,
        f: false,
        e: lp.e && rp.e,
        m: lp.m && rp.m && lp.e && rp.e,
        s: lp.s && rp.s,
        x: lp.x || rp.x,
        g: lp.g || rp.g,
        h: lp.h || rp.h,
        i: lp.i || rp.i,
        j: lp.j || rp.j,
        k: lp.k && rp.k && checkTimeLocksMix({ ...emptyProps(), g: lp.g || rp.g, h: lp.h || rp.h, i: lp.i || rp.i, j: lp.j || rp.j }),
      });
    }

    case "or_c": {
      const leftType = computeType(node.left, ctx);
      const rightType = computeType(node.right, ctx);
      const lp = leftType.props;
      const rp = rightType.props;

      // or_c(X,Y): Bdu,V -> B
      if (leftType.base !== BaseType.B || !lp.d || !lp.u) {
        throw new Error("or_c left must be Bdu");
      }
      if (rightType.base !== BaseType.V) {
        throw new Error("or_c right must be V");
      }

      return makeType(BaseType.B, {
        z: lp.z && rp.z,
        o: lp.o && rp.z,
        n: false,
        u: true,
        d: false,
        f: true,
        e: false,
        m: lp.m && rp.m && (lp.e || rp.f),
        s: lp.s || rp.s,
        x: lp.x || rp.x,
        g: lp.g || rp.g,
        h: lp.h || rp.h,
        i: lp.i || rp.i,
        j: lp.j || rp.j,
        k: lp.k && rp.k && checkTimeLocksMix({ ...emptyProps(), g: lp.g || rp.g, h: lp.h || rp.h, i: lp.i || rp.i, j: lp.j || rp.j }),
      });
    }

    case "or_d": {
      const leftType = computeType(node.left, ctx);
      const rightType = computeType(node.right, ctx);
      const lp = leftType.props;
      const rp = rightType.props;

      // or_d(X,Y): Bdu,B -> B
      if (leftType.base !== BaseType.B || !lp.d || !lp.u) {
        throw new Error("or_d left must be Bdu");
      }
      if (rightType.base !== BaseType.B) {
        throw new Error("or_d right must be B");
      }

      return makeType(BaseType.B, {
        z: lp.z && rp.z,
        o: lp.o && rp.z,
        n: false,
        u: rp.u,
        d: rp.d,
        f: rp.f,
        e: lp.e && rp.e && (lp.s || rp.s),
        m: lp.m && rp.m && lp.e && (lp.s || rp.f),
        s: lp.s || rp.s,
        x: lp.x || rp.x,
        g: lp.g || rp.g,
        h: lp.h || rp.h,
        i: lp.i || rp.i,
        j: lp.j || rp.j,
        k: lp.k && rp.k && checkTimeLocksMix({ ...emptyProps(), g: lp.g || rp.g, h: lp.h || rp.h, i: lp.i || rp.i, j: lp.j || rp.j }),
      });
    }

    case "or_i": {
      const leftType = computeType(node.left, ctx);
      const rightType = computeType(node.right, ctx);
      const lp = leftType.props;
      const rp = rightType.props;

      // or_i(X,Y): same base type for both
      if (leftType.base !== rightType.base) {
        throw new Error("or_i requires same base type");
      }

      return makeType(leftType.base, {
        z: false, // OP_IF adds stack element
        o: lp.z && rp.z,
        n: false,
        u: lp.u && rp.u,
        d: (lp.d || rp.f) && (rp.d || lp.f),
        f: lp.f && rp.f,
        e: (lp.e && rp.f) || (rp.e && lp.f),
        m: lp.m && rp.m && (lp.s || rp.s),
        s: lp.s && rp.s,
        x: lp.x || rp.x,
        g: lp.g || rp.g,
        h: lp.h || rp.h,
        i: lp.i || rp.i,
        j: lp.j || rp.j,
        k: lp.k && rp.k && checkTimeLocksMix({ ...emptyProps(), g: lp.g || rp.g, h: lp.h || rp.h, i: lp.i || rp.i, j: lp.j || rp.j }),
      });
    }

    case "andor": {
      const condType = computeType(node.cond, ctx);
      const trueType = computeType(node.ifTrue, ctx);
      const falseType = computeType(node.ifFalse, ctx);
      const cp = condType.props;
      const tp = trueType.props;
      const fp = falseType.props;

      // andor(X,Y,Z): Bdu,B,B -> B
      if (condType.base !== BaseType.B || !cp.d || !cp.u) {
        throw new Error("andor cond must be Bdu");
      }
      if (trueType.base !== falseType.base) {
        throw new Error("andor branches must have same base type");
      }

      return makeType(trueType.base, {
        z: cp.z && tp.z && fp.z,
        o: cp.o && tp.z && fp.z,
        n: false,
        u: tp.u && fp.u,
        d: (tp.d || cp.f) && fp.d,
        f: tp.f && fp.f,
        e: (tp.e && fp.e && cp.s) || (cp.e && fp.e && tp.f),
        m: cp.m && tp.m && fp.m && cp.e && (cp.s || tp.f || fp.f),
        s: tp.s || fp.s || cp.s,
        x: tp.x || fp.x || cp.x,
        g: cp.g || tp.g || fp.g,
        h: cp.h || tp.h || fp.h,
        i: cp.i || tp.i || fp.i,
        j: cp.j || tp.j || fp.j,
        k: cp.k && tp.k && fp.k,
      });
    }

    case "thresh": {
      if (node.subs.length < 1) {
        throw new Error("thresh requires at least one sub");
      }

      // thresh(k,X1,...,Xn): all must be Wdu except first which must be Bdu
      const firstType = computeType(node.subs[0], ctx);
      if (firstType.base !== BaseType.B || !firstType.props.d || !firstType.props.u) {
        throw new Error("thresh first sub must be Bdu");
      }

      let z = firstType.props.z;
      let o = firstType.props.o;
      let m = firstType.props.m;
      let s = firstType.props.s;
      let e = firstType.props.e;
      let g = firstType.props.g;
      let h = firstType.props.h;
      let i = firstType.props.i;
      let j = firstType.props.j;
      let k = firstType.props.k;

      let allE = e;
      let countS = s ? 1 : 0;

      for (let idx = 1; idx < node.subs.length; idx++) {
        const subType = computeType(node.subs[idx], ctx);
        if (subType.base !== BaseType.W || !subType.props.d || !subType.props.u) {
          throw new Error(`thresh sub ${idx} must be Wdu`);
        }

        z = z && subType.props.z;
        o = o && subType.props.z;
        m = m && subType.props.m;
        s = s || subType.props.s;
        allE = allE && subType.props.e;
        if (subType.props.s) countS++;
        g = g || subType.props.g;
        h = h || subType.props.h;
        i = i || subType.props.i;
        j = j || subType.props.j;
        k = k && subType.props.k;
      }

      // thresh is malleable if not all subs are e or if k < n and not enough s
      const n = node.subs.length;
      e = allE && (countS >= n - node.threshold);
      m = m && e;

      return makeType(BaseType.B, {
        z,
        o,
        n: false,
        u: true,
        d: true,
        f: false,
        e,
        m,
        s,
        x: false,
        g,
        h,
        i,
        j,
        k: k && checkTimeLocksMix({ ...emptyProps(), g, h, i, j }),
      });
    }

    case "multi":
      // multi(k,K1,...,Kn): type Bnudemsxk
      return makeType(BaseType.B, {
        n: true,
        u: true,
        d: true,
        e: true,
        m: true,
        s: true,
        x: false,
      });

    case "multi_a":
      // multi_a(k,K1,...,Kn): type Bnudemsxk (Tapscript version)
      return makeType(BaseType.B, {
        n: true,
        u: true,
        d: true,
        e: true,
        m: true,
        s: true,
        x: false,
      });

    // Wrappers
    case "wrap_a": {
      const innerType = computeType(node.inner, ctx);
      // a:X converts B -> W (also accepts K via implicit c:)
      if (innerType.base !== BaseType.B && innerType.base !== BaseType.K) {
        throw new Error("wrap_a requires B or K type");
      }

      return makeType(BaseType.W, {
        ...innerType.props,
        u: innerType.props.u,
        d: innerType.props.d,
      });
    }

    case "wrap_s": {
      const innerType = computeType(node.inner, ctx);
      // s:X converts Bo -> W
      if (innerType.base !== BaseType.B || !innerType.props.o) {
        throw new Error("wrap_s requires Bo type");
      }

      return makeType(BaseType.W, {
        ...innerType.props,
        o: false, // s: adds a swap
      });
    }

    case "wrap_c": {
      const innerType = computeType(node.inner, ctx);
      // c:X converts K -> B
      if (innerType.base !== BaseType.K) {
        throw new Error("wrap_c requires K type");
      }

      return makeType(BaseType.B, {
        ...innerType.props,
        u: true,
        s: true,
      });
    }

    case "wrap_d": {
      const innerType = computeType(node.inner, ctx);
      // d:X converts Vz -> B
      if (innerType.base !== BaseType.V || !innerType.props.z) {
        throw new Error("wrap_d requires Vz type");
      }

      return makeType(BaseType.B, {
        ...innerType.props,
        o: true,
        n: false,
        u: true,
        d: true,
        e: false,
        f: false,
      });
    }

    case "wrap_v": {
      const innerType = computeType(node.inner, ctx);
      // v:X converts B -> V (also accepts K via implicit c:)
      if (innerType.base !== BaseType.B && innerType.base !== BaseType.K) {
        throw new Error("wrap_v requires B or K type");
      }

      return makeType(BaseType.V, {
        ...innerType.props,
        u: false,
        d: false,
        f: true,
        e: false,
        x: true,
      });
    }

    case "wrap_j": {
      const innerType = computeType(node.inner, ctx);
      // j:X converts Bn -> B
      if (innerType.base !== BaseType.B || !innerType.props.n) {
        throw new Error("wrap_j requires Bn type");
      }

      return makeType(BaseType.B, {
        ...innerType.props,
        o: true,
        n: false,
        u: true,
        d: true,
        e: innerType.props.f,
        f: false,
      });
    }

    case "wrap_n": {
      const innerType = computeType(node.inner, ctx);
      // n:X converts B -> B
      if (innerType.base !== BaseType.B) {
        throw new Error("wrap_n requires B type");
      }

      return makeType(BaseType.B, {
        ...innerType.props,
        u: true,
        n: false,
      });
    }

    default:
      throw new Error(`Unknown node type: ${(node as MiniscriptNode).type}`);
  }
}

// =============================================================================
// Parsing
// =============================================================================

/**
 * Parser state for recursive descent parsing.
 */
interface ParserState {
  input: string;
  pos: number;
  ctx: MiniscriptContext;
}

/**
 * Parse a miniscript expression from a string.
 */
export function parseMiniscript(
  input: string,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): MiniscriptNode {
  const state: ParserState = { input, pos: 0, ctx };
  const node = parseExpression(state);

  if (state.pos !== input.length) {
    throw new Error(
      `Unexpected characters at position ${state.pos}: ${input.slice(state.pos)}`
    );
  }

  return node;
}

function parseExpression(state: ParserState): MiniscriptNode {
  // Try wrappers first (a:, s:, c:, d:, v:, j:, n:, t:, l:, u:)
  const wrapperResult = tryParseWrapper(state);
  if (wrapperResult) {
    return wrapperResult;
  }

  // Try each fragment type
  return parseFragment(state);
}

function tryParseWrapper(state: ParserState): MiniscriptNode | null {
  const { input, pos } = state;

  // Check for wrapper prefix
  if (pos + 1 < input.length && input[pos + 1] === ":") {
    const prefix = input[pos];
    state.pos = pos + 2;

    const inner = parseExpression(state);

    switch (prefix) {
      case "a":
        return { type: "wrap_a", inner };
      case "s":
        return { type: "wrap_s", inner };
      case "c":
        return { type: "wrap_c", inner };
      case "d":
        return { type: "wrap_d", inner };
      case "v":
        return { type: "wrap_v", inner };
      case "j":
        return { type: "wrap_j", inner };
      case "n":
        return { type: "wrap_n", inner };
      case "t":
        // t:X = and_v(X,1)
        return {
          type: "and_v",
          left: { type: "wrap_v", inner },
          right: { type: "just_1" },
        };
      case "l":
        // l:X = or_i(0,X)
        return {
          type: "or_i",
          left: { type: "just_0" },
          right: inner,
        };
      case "u":
        // u:X = or_i(X,0)
        return {
          type: "or_i",
          left: inner,
          right: { type: "just_0" },
        };
      default:
        // Not a wrapper, restore position
        state.pos = pos;
        return null;
    }
  }

  return null;
}

function parseFragment(state: ParserState): MiniscriptNode {
  const { input, pos } = state;

  // Try to match a fragment name
  const fragments = [
    "pk_k",
    "pk_h",
    "pk",
    "pkh",
    "older",
    "after",
    "sha256",
    "hash256",
    "ripemd160",
    "hash160",
    "and_v",
    "and_b",
    "or_b",
    "or_c",
    "or_d",
    "or_i",
    "andor",
    "thresh",
    "multi_a",
    "multi",
    "0",
    "1",
  ];

  for (const frag of fragments) {
    if (input.slice(pos).startsWith(frag)) {
      if (frag === "0") {
        state.pos = pos + 1;
        return { type: "just_0" };
      }
      if (frag === "1") {
        state.pos = pos + 1;
        return { type: "just_1" };
      }

      // Expect opening paren
      if (input[pos + frag.length] !== "(") {
        continue;
      }
      state.pos = pos + frag.length + 1;

      const node = parseFragmentArgs(state, frag);

      // Expect closing paren
      if (input[state.pos] !== ")") {
        throw new Error(`Expected ')' at position ${state.pos}`);
      }
      state.pos++;

      return node;
    }
  }

  throw new Error(`Unknown fragment at position ${pos}: ${input.slice(pos, pos + 20)}`);
}

function parseFragmentArgs(state: ParserState, frag: string): MiniscriptNode {
  switch (frag) {
    case "pk":
      // pk(KEY) is syntactic sugar for c:pk_k(KEY)
      return { type: "wrap_c", inner: parsePkK(state) };
    case "pk_k":
      return parsePkK(state);
    case "pkh":
      // pkh(KEY) is syntactic sugar for c:pk_h(KEY)
      return { type: "wrap_c", inner: parsePkH(state) };
    case "pk_h":
      return parsePkH(state);
    case "older":
      return parseOlder(state);
    case "after":
      return parseAfter(state);
    case "sha256":
      return parseSha256(state);
    case "hash256":
      return parseHash256(state);
    case "ripemd160":
      return parseRipemd160(state);
    case "hash160":
      return parseHash160(state);
    case "and_v":
      return parseAndV(state);
    case "and_b":
      return parseAndB(state);
    case "or_b":
      return parseOrB(state);
    case "or_c":
      return parseOrC(state);
    case "or_d":
      return parseOrD(state);
    case "or_i":
      return parseOrI(state);
    case "andor":
      return parseAndOr(state);
    case "thresh":
      return parseThresh(state);
    case "multi":
      return parseMulti(state);
    case "multi_a":
      return parseMultiA(state);
    default:
      throw new Error(`Unknown fragment: ${frag}`);
  }
}

function parseHex(state: ParserState): Buffer {
  const { input, pos } = state;
  let end = pos;
  while (end < input.length && /[0-9a-fA-F]/.test(input[end])) {
    end++;
  }
  if (end === pos) {
    throw new Error(`Expected hex at position ${pos}`);
  }
  const hex = input.slice(pos, end);
  state.pos = end;
  return Buffer.from(hex, "hex");
}

function parseNumber(state: ParserState): number {
  const { input, pos } = state;
  let end = pos;
  while (end < input.length && /[0-9]/.test(input[end])) {
    end++;
  }
  if (end === pos) {
    throw new Error(`Expected number at position ${pos}`);
  }
  const num = parseInt(input.slice(pos, end), 10);
  state.pos = end;
  return num;
}

function expectComma(state: ParserState): void {
  if (state.input[state.pos] !== ",") {
    throw new Error(`Expected ',' at position ${state.pos}`);
  }
  state.pos++;
}

function parsePkK(state: ParserState): PkKNode {
  const key = parseHex(state);
  if (key.length !== 33 && key.length !== 32 && key.length !== 65) {
    throw new Error(`Invalid key length: ${key.length}`);
  }
  return { type: "pk_k", key };
}

function parsePkH(state: ParserState): PkHNode {
  const keyOrHash = parseHex(state);
  // If 20 bytes, it's a hash; otherwise it's a key
  if (keyOrHash.length === 20) {
    return { type: "pk_h", keyHash: keyOrHash };
  }
  if (keyOrHash.length === 33 || keyOrHash.length === 32 || keyOrHash.length === 65) {
    return { type: "pk_h", keyHash: hash160(keyOrHash), key: keyOrHash };
  }
  throw new Error(`Invalid pk_h argument length: ${keyOrHash.length}`);
}

function parseOlder(state: ParserState): OlderNode {
  const sequence = parseNumber(state);
  if (sequence <= 0 || sequence >= 0x80000000) {
    throw new Error(`Invalid sequence: ${sequence}`);
  }
  return { type: "older", sequence };
}

function parseAfter(state: ParserState): AfterNode {
  const locktime = parseNumber(state);
  if (locktime <= 0 || locktime >= 0x100000000) {
    throw new Error(`Invalid locktime: ${locktime}`);
  }
  return { type: "after", locktime };
}

function parseSha256(state: ParserState): Sha256Node {
  const hash = parseHex(state);
  if (hash.length !== 32) {
    throw new Error(`sha256 hash must be 32 bytes, got ${hash.length}`);
  }
  return { type: "sha256", hash };
}

function parseHash256(state: ParserState): Hash256Node {
  const hash = parseHex(state);
  if (hash.length !== 32) {
    throw new Error(`hash256 hash must be 32 bytes, got ${hash.length}`);
  }
  return { type: "hash256", hash };
}

function parseRipemd160(state: ParserState): Ripemd160Node {
  const hash = parseHex(state);
  if (hash.length !== 20) {
    throw new Error(`ripemd160 hash must be 20 bytes, got ${hash.length}`);
  }
  return { type: "ripemd160", hash };
}

function parseHash160(state: ParserState): Hash160Node {
  const hash = parseHex(state);
  if (hash.length !== 20) {
    throw new Error(`hash160 hash must be 20 bytes, got ${hash.length}`);
  }
  return { type: "hash160", hash };
}

function parseAndV(state: ParserState): AndVNode {
  const left = parseExpression(state);
  expectComma(state);
  const right = parseExpression(state);
  return { type: "and_v", left, right };
}

function parseAndB(state: ParserState): AndBNode {
  const left = parseExpression(state);
  expectComma(state);
  const right = parseExpression(state);
  return { type: "and_b", left, right };
}

function parseOrB(state: ParserState): OrBNode {
  const left = parseExpression(state);
  expectComma(state);
  const right = parseExpression(state);
  return { type: "or_b", left, right };
}

function parseOrC(state: ParserState): OrCNode {
  const left = parseExpression(state);
  expectComma(state);
  const right = parseExpression(state);
  return { type: "or_c", left, right };
}

function parseOrD(state: ParserState): OrDNode {
  const left = parseExpression(state);
  expectComma(state);
  const right = parseExpression(state);
  return { type: "or_d", left, right };
}

function parseOrI(state: ParserState): OrINode {
  const left = parseExpression(state);
  expectComma(state);
  const right = parseExpression(state);
  return { type: "or_i", left, right };
}

function parseAndOr(state: ParserState): AndOrNode {
  const cond = parseExpression(state);
  expectComma(state);
  const ifTrue = parseExpression(state);
  expectComma(state);
  const ifFalse = parseExpression(state);
  return { type: "andor", cond, ifTrue, ifFalse };
}

function parseThresh(state: ParserState): ThreshNode {
  const threshold = parseNumber(state);
  expectComma(state);

  const subs: MiniscriptNode[] = [];
  subs.push(parseExpression(state));

  while (state.input[state.pos] === ",") {
    state.pos++;
    subs.push(parseExpression(state));
  }

  if (threshold < 1 || threshold > subs.length) {
    throw new Error(`Invalid threshold ${threshold} for ${subs.length} subs`);
  }

  return { type: "thresh", threshold, subs };
}

function parseMulti(state: ParserState): MultiNode {
  const threshold = parseNumber(state);
  expectComma(state);

  const keys: Buffer[] = [];
  keys.push(parseHex(state));

  while (state.input[state.pos] === ",") {
    state.pos++;
    keys.push(parseHex(state));
  }

  if (threshold < 1 || threshold > keys.length) {
    throw new Error(`Invalid threshold ${threshold} for ${keys.length} keys`);
  }

  if (state.ctx === MiniscriptContext.P2WSH && keys.length > MAX_MULTISIG_KEYS) {
    throw new Error(`Too many keys for multi: ${keys.length} > ${MAX_MULTISIG_KEYS}`);
  }

  return { type: "multi", threshold, keys };
}

function parseMultiA(state: ParserState): MultiANode {
  const threshold = parseNumber(state);
  expectComma(state);

  const keys: Buffer[] = [];
  keys.push(parseHex(state));

  while (state.input[state.pos] === ",") {
    state.pos++;
    keys.push(parseHex(state));
  }

  if (threshold < 1 || threshold > keys.length) {
    throw new Error(`Invalid threshold ${threshold} for ${keys.length} keys`);
  }

  if (keys.length > MAX_MULTI_A_KEYS) {
    throw new Error(`Too many keys for multi_a: ${keys.length} > ${MAX_MULTI_A_KEYS}`);
  }

  return { type: "multi_a", threshold, keys };
}

// =============================================================================
// Script Compilation
// =============================================================================

/**
 * Compile a miniscript AST to Bitcoin Script.
 */
export function compileScript(
  node: MiniscriptNode,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): Buffer {
  const chunks: Buffer[] = [];
  compileNode(node, chunks, ctx);
  return Buffer.concat(chunks);
}

/**
 * Push a number onto the script.
 */
function pushNumber(n: number): Buffer {
  if (n === 0) {
    return Buffer.from([Opcode.OP_0]);
  }
  if (n >= 1 && n <= 16) {
    return Buffer.from([Opcode.OP_1 - 1 + n]);
  }
  if (n === -1) {
    return Buffer.from([Opcode.OP_1NEGATE]);
  }

  // CScriptNum encoding
  const neg = n < 0;
  let absN = Math.abs(n);
  const bytes: number[] = [];

  while (absN > 0) {
    bytes.push(absN & 0xff);
    absN >>= 8;
  }

  // If high bit set, add an extra byte for the sign
  if (bytes.length > 0 && bytes[bytes.length - 1] & 0x80) {
    bytes.push(neg ? 0x80 : 0x00);
  } else if (neg && bytes.length > 0) {
    bytes[bytes.length - 1] |= 0x80;
  }

  const data = Buffer.from(bytes);
  return pushData(data);
}

/**
 * Push data onto the script.
 */
function pushData(data: Buffer): Buffer {
  const len = data.length;
  if (len === 0) {
    return Buffer.from([Opcode.OP_0]);
  }
  if (len <= 75) {
    return Buffer.concat([Buffer.from([len]), data]);
  }
  if (len <= 255) {
    return Buffer.concat([Buffer.from([Opcode.OP_PUSHDATA1, len]), data]);
  }
  if (len <= 65535) {
    const header = Buffer.alloc(3);
    header[0] = Opcode.OP_PUSHDATA2;
    header.writeUInt16LE(len, 1);
    return Buffer.concat([header, data]);
  }
  const header = Buffer.alloc(5);
  header[0] = Opcode.OP_PUSHDATA4;
  header.writeUInt32LE(len, 1);
  return Buffer.concat([header, data]);
}

function compileNode(
  node: MiniscriptNode,
  chunks: Buffer[],
  ctx: MiniscriptContext
): void {
  switch (node.type) {
    case "just_0":
      chunks.push(Buffer.from([Opcode.OP_0]));
      break;

    case "just_1":
      chunks.push(Buffer.from([Opcode.OP_1]));
      break;

    case "pk_k":
      // <key>
      chunks.push(pushData(node.key));
      break;

    case "pk_h":
      // OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY
      chunks.push(Buffer.from([Opcode.OP_DUP, Opcode.OP_HASH160]));
      chunks.push(pushData(node.keyHash));
      chunks.push(Buffer.from([Opcode.OP_EQUALVERIFY]));
      break;

    case "older":
      // <n> OP_CHECKSEQUENCEVERIFY
      chunks.push(pushNumber(node.sequence));
      chunks.push(Buffer.from([Opcode.OP_CHECKSEQUENCEVERIFY]));
      break;

    case "after":
      // <n> OP_CHECKLOCKTIMEVERIFY
      chunks.push(pushNumber(node.locktime));
      chunks.push(Buffer.from([Opcode.OP_CHECKLOCKTIMEVERIFY]));
      break;

    case "sha256":
      // OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
      chunks.push(Buffer.from([Opcode.OP_SIZE]));
      chunks.push(pushNumber(32));
      chunks.push(Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_SHA256]));
      chunks.push(pushData(node.hash));
      chunks.push(Buffer.from([Opcode.OP_EQUAL]));
      break;

    case "hash256":
      // OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 <hash> OP_EQUAL
      chunks.push(Buffer.from([Opcode.OP_SIZE]));
      chunks.push(pushNumber(32));
      chunks.push(Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_HASH256]));
      chunks.push(pushData(node.hash));
      chunks.push(Buffer.from([Opcode.OP_EQUAL]));
      break;

    case "ripemd160":
      // OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 <hash> OP_EQUAL
      chunks.push(Buffer.from([Opcode.OP_SIZE]));
      chunks.push(pushNumber(32));
      chunks.push(Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_RIPEMD160]));
      chunks.push(pushData(node.hash));
      chunks.push(Buffer.from([Opcode.OP_EQUAL]));
      break;

    case "hash160":
      // OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hash> OP_EQUAL
      chunks.push(Buffer.from([Opcode.OP_SIZE]));
      chunks.push(pushNumber(32));
      chunks.push(Buffer.from([Opcode.OP_EQUALVERIFY, Opcode.OP_HASH160]));
      chunks.push(pushData(node.hash));
      chunks.push(Buffer.from([Opcode.OP_EQUAL]));
      break;

    case "and_v":
      // [X] [Y]
      compileNode(node.left, chunks, ctx);
      compileNode(node.right, chunks, ctx);
      break;

    case "and_b":
      // [X] [Y] OP_BOOLAND
      compileNode(node.left, chunks, ctx);
      compileNode(node.right, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_BOOLAND]));
      break;

    case "or_b":
      // [X] [Y] OP_BOOLOR
      compileNode(node.left, chunks, ctx);
      compileNode(node.right, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_BOOLOR]));
      break;

    case "or_c":
      // [X] OP_NOTIF [Y] OP_ENDIF
      compileNode(node.left, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_NOTIF]));
      compileNode(node.right, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ENDIF]));
      break;

    case "or_d":
      // [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
      compileNode(node.left, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_IFDUP, Opcode.OP_NOTIF]));
      compileNode(node.right, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ENDIF]));
      break;

    case "or_i":
      // OP_IF [X] OP_ELSE [Y] OP_ENDIF
      chunks.push(Buffer.from([Opcode.OP_IF]));
      compileNode(node.left, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ELSE]));
      compileNode(node.right, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ENDIF]));
      break;

    case "andor":
      // [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
      compileNode(node.cond, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_NOTIF]));
      compileNode(node.ifFalse, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ELSE]));
      compileNode(node.ifTrue, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ENDIF]));
      break;

    case "thresh": {
      // [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
      compileNode(node.subs[0], chunks, ctx);
      for (let i = 1; i < node.subs.length; i++) {
        compileNode(node.subs[i], chunks, ctx);
        chunks.push(Buffer.from([Opcode.OP_ADD]));
      }
      chunks.push(pushNumber(node.threshold));
      chunks.push(Buffer.from([Opcode.OP_EQUAL]));
      break;
    }

    case "multi": {
      // [k] [key_n]* [n] OP_CHECKMULTISIG
      chunks.push(pushNumber(node.threshold));
      for (const key of node.keys) {
        chunks.push(pushData(key));
      }
      chunks.push(pushNumber(node.keys.length));
      chunks.push(Buffer.from([Opcode.OP_CHECKMULTISIG]));
      break;
    }

    case "multi_a": {
      // [key_0] OP_CHECKSIG ([key_n] OP_CHECKSIGADD)* [k] OP_NUMEQUAL
      chunks.push(pushData(node.keys[0]));
      chunks.push(Buffer.from([Opcode.OP_CHECKSIG]));
      for (let i = 1; i < node.keys.length; i++) {
        chunks.push(pushData(node.keys[i]));
        chunks.push(Buffer.from([Opcode.OP_CHECKSIGADD]));
      }
      chunks.push(pushNumber(node.threshold));
      chunks.push(Buffer.from([Opcode.OP_NUMEQUAL]));
      break;
    }

    case "wrap_a":
      // OP_TOALTSTACK [X] OP_FROMALTSTACK
      chunks.push(Buffer.from([Opcode.OP_TOALTSTACK]));
      compileNode(node.inner, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_FROMALTSTACK]));
      break;

    case "wrap_s":
      // OP_SWAP [X]
      chunks.push(Buffer.from([Opcode.OP_SWAP]));
      compileNode(node.inner, chunks, ctx);
      break;

    case "wrap_c":
      // [X] OP_CHECKSIG
      compileNode(node.inner, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_CHECKSIG]));
      break;

    case "wrap_d":
      // OP_DUP OP_IF [X] OP_ENDIF
      chunks.push(Buffer.from([Opcode.OP_DUP, Opcode.OP_IF]));
      compileNode(node.inner, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ENDIF]));
      break;

    case "wrap_v":
      // [X] OP_VERIFY (or fuse with last opcode)
      compileNode(node.inner, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_VERIFY]));
      break;

    case "wrap_j":
      // OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
      chunks.push(Buffer.from([Opcode.OP_SIZE, Opcode.OP_0NOTEQUAL, Opcode.OP_IF]));
      compileNode(node.inner, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_ENDIF]));
      break;

    case "wrap_n":
      // [X] OP_0NOTEQUAL
      compileNode(node.inner, chunks, ctx);
      chunks.push(Buffer.from([Opcode.OP_0NOTEQUAL]));
      break;

    default:
      throw new Error(`Cannot compile node type: ${(node as MiniscriptNode).type}`);
  }
}

// =============================================================================
// Satisfaction
// =============================================================================

/**
 * Availability of a satisfaction input.
 */
export enum Availability {
  /** Not available */
  NO = "no",
  /** Available */
  YES = "yes",
  /** May or may not be available (for analysis) */
  MAYBE = "maybe",
}

/**
 * Satisfaction context - provides available keys, preimages, timelocks.
 */
export interface SatisfactionContext {
  /** Available signatures by public key hex */
  signatures: Map<string, Buffer>;
  /** Available preimages by hash hex */
  preimages: Map<string, Buffer>;
  /** Current block height (for CLTV) */
  blockHeight?: number;
  /** Current median time past (for CLTV with time) */
  medianTimePast?: number;
  /** Sequence number for spending input (for CSV) */
  sequence?: number;
}

/**
 * A single witness stack element.
 */
export interface WitnessElement {
  data: Buffer;
  /** Whether this element has a signature (affects malleability) */
  hasSig: boolean;
}

/**
 * Result of satisfaction/dissatisfaction computation.
 */
export interface SatisfactionResult {
  /** Whether satisfaction is possible */
  available: Availability;
  /** Witness stack (bottom to top) */
  stack: WitnessElement[];
  /** Whether this satisfaction is malleable */
  malleable: boolean;
  /** Serialized size in bytes */
  size: number;
}

/**
 * Combined satisfaction and dissatisfaction result.
 */
export interface InputResult {
  sat: SatisfactionResult;
  nsat: SatisfactionResult;
}

/**
 * Create an unavailable satisfaction result.
 */
function unavailable(): SatisfactionResult {
  return {
    available: Availability.NO,
    stack: [],
    malleable: true,
    size: 0,
  };
}

/**
 * Create an empty satisfaction result (for zero-arg nodes).
 */
function empty(): SatisfactionResult {
  return {
    available: Availability.YES,
    stack: [],
    malleable: false,
    size: 0,
  };
}

/**
 * Create a single-element satisfaction result.
 */
function single(data: Buffer, hasSig: boolean = false): SatisfactionResult {
  return {
    available: Availability.YES,
    stack: [{ data, hasSig }],
    malleable: !hasSig,
    size: data.length + (data.length < 75 ? 1 : data.length < 256 ? 2 : 3),
  };
}

/**
 * Concatenate two satisfaction results.
 */
function concat(
  a: SatisfactionResult,
  b: SatisfactionResult
): SatisfactionResult {
  if (a.available === Availability.NO || b.available === Availability.NO) {
    return unavailable();
  }
  return {
    available:
      a.available === Availability.YES && b.available === Availability.YES
        ? Availability.YES
        : Availability.MAYBE,
    stack: [...a.stack, ...b.stack],
    malleable: a.malleable || b.malleable,
    size: a.size + b.size,
  };
}

/**
 * Choose the smaller of two satisfaction results.
 */
function choose(
  a: SatisfactionResult,
  b: SatisfactionResult
): SatisfactionResult {
  if (a.available === Availability.NO) return b;
  if (b.available === Availability.NO) return a;

  // Prefer non-malleable
  if (a.malleable && !b.malleable) return b;
  if (!a.malleable && b.malleable) return a;

  // Then prefer smaller
  return a.size <= b.size ? a : b;
}

/**
 * Compute satisfaction and dissatisfaction for a miniscript node.
 */
export function computeSatisfaction(
  node: MiniscriptNode,
  satCtx: SatisfactionContext,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): InputResult {
  switch (node.type) {
    case "just_0":
      // 0: dissatisfied with empty, cannot satisfy
      return {
        sat: unavailable(),
        nsat: empty(),
      };

    case "just_1":
      // 1: satisfied with empty, cannot dissatisfy
      return {
        sat: empty(),
        nsat: unavailable(),
      };

    case "pk_k": {
      // pk_k(KEY): sig for sat, empty for nsat
      const keyHex = node.key.toString("hex");
      const sig = satCtx.signatures.get(keyHex);

      if (sig) {
        return {
          sat: single(sig, true),
          nsat: single(Buffer.alloc(0), false),
        };
      }
      return {
        sat: unavailable(),
        nsat: single(Buffer.alloc(0), false),
      };
    }

    case "pk_h": {
      // pk_h(KEY): <sig> <pubkey> for sat, <empty> <pubkey> for nsat
      if (!node.key) {
        // Can't satisfy without knowing the key
        return {
          sat: unavailable(),
          nsat: unavailable(),
        };
      }

      const keyHex = node.key.toString("hex");
      const sig = satCtx.signatures.get(keyHex);
      const pubkeyElement: WitnessElement = { data: node.key, hasSig: false };

      if (sig) {
        return {
          sat: {
            available: Availability.YES,
            stack: [{ data: sig, hasSig: true }, pubkeyElement],
            malleable: false,
            size: sig.length + node.key.length + 2,
          },
          nsat: {
            available: Availability.YES,
            stack: [{ data: Buffer.alloc(0), hasSig: false }, pubkeyElement],
            malleable: true,
            size: 1 + node.key.length + 1,
          },
        };
      }
      return {
        sat: unavailable(),
        nsat: {
          available: Availability.YES,
          stack: [{ data: Buffer.alloc(0), hasSig: false }, pubkeyElement],
          malleable: true,
          size: 1 + node.key.length + 1,
        },
      };
    }

    case "older": {
      // older(n): sat if sequence allows, otherwise unavailable
      const seq = satCtx.sequence ?? 0;
      const nValue = node.sequence;

      // Check if sequence is compatible
      const seqDisabled = (seq & 0x80000000) !== 0;
      const seqType = (seq & SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0;
      const reqType = (nValue & SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0;
      const seqMask = seq & 0xffff;
      const reqMask = nValue & 0xffff;

      if (!seqDisabled && seqType === reqType && seqMask >= reqMask) {
        return {
          sat: empty(),
          nsat: unavailable(), // older cannot be dissatisfied
        };
      }
      return {
        sat: unavailable(),
        nsat: unavailable(),
      };
    }

    case "after": {
      // after(n): sat if locktime allows
      const height = satCtx.blockHeight ?? 0;
      const time = satCtx.medianTimePast ?? 0;
      const nValue = node.locktime;

      if (nValue < LOCKTIME_THRESHOLD) {
        // Height-based
        if (height >= nValue) {
          return {
            sat: empty(),
            nsat: unavailable(),
          };
        }
      } else {
        // Time-based
        if (time >= nValue) {
          return {
            sat: empty(),
            nsat: unavailable(),
          };
        }
      }
      return {
        sat: unavailable(),
        nsat: unavailable(),
      };
    }

    case "sha256":
    case "hash256":
    case "ripemd160":
    case "hash160": {
      // hash(H): <preimage> for sat, <0x00...00> (32 bytes) for nsat
      const hashHex = node.hash.toString("hex");
      const preimage = satCtx.preimages.get(hashHex);

      if (preimage) {
        return {
          sat: single(preimage, false),
          nsat: single(Buffer.alloc(32), false), // 32 zero bytes (malleable)
        };
      }
      return {
        sat: unavailable(),
        nsat: single(Buffer.alloc(32), false),
      };
    }

    case "and_v": {
      const leftResult = computeSatisfaction(node.left, satCtx, ctx);
      const rightResult = computeSatisfaction(node.right, satCtx, ctx);

      // and_v: sat = sat(X) + sat(Y), nsat = nsat(Y) (X is V, cannot be nsat)
      return {
        sat: concat(leftResult.sat, rightResult.sat),
        nsat: rightResult.nsat,
      };
    }

    case "and_b": {
      const leftResult = computeSatisfaction(node.left, satCtx, ctx);
      const rightResult = computeSatisfaction(node.right, satCtx, ctx);

      // and_b: sat = sat(X) + sat(Y), nsat = nsat(X) + nsat(Y) or nsat(X) + sat(Y) or sat(X) + nsat(Y)
      const sat = concat(leftResult.sat, rightResult.sat);
      const nsat1 = concat(leftResult.nsat, rightResult.nsat);
      const nsat2 = concat(leftResult.nsat, rightResult.sat);
      const nsat3 = concat(leftResult.sat, rightResult.nsat);

      return {
        sat,
        nsat: choose(nsat1, choose(nsat2, nsat3)),
      };
    }

    case "or_b": {
      const leftResult = computeSatisfaction(node.left, satCtx, ctx);
      const rightResult = computeSatisfaction(node.right, satCtx, ctx);

      // or_b: sat = sat(X) + nsat(Y) or nsat(X) + sat(Y), nsat = nsat(X) + nsat(Y)
      const sat1 = concat(leftResult.sat, rightResult.nsat);
      const sat2 = concat(leftResult.nsat, rightResult.sat);

      return {
        sat: choose(sat1, sat2),
        nsat: concat(leftResult.nsat, rightResult.nsat),
      };
    }

    case "or_c": {
      const leftResult = computeSatisfaction(node.left, satCtx, ctx);
      const rightResult = computeSatisfaction(node.right, satCtx, ctx);

      // or_c: sat = sat(X) or nsat(X) + sat(Y), cannot nsat
      const sat = choose(leftResult.sat, concat(leftResult.nsat, rightResult.sat));

      return {
        sat,
        nsat: unavailable(),
      };
    }

    case "or_d": {
      const leftResult = computeSatisfaction(node.left, satCtx, ctx);
      const rightResult = computeSatisfaction(node.right, satCtx, ctx);

      // or_d: sat = sat(X) or nsat(X) + sat(Y), nsat = nsat(X) + nsat(Y)
      const sat = choose(leftResult.sat, concat(leftResult.nsat, rightResult.sat));

      return {
        sat,
        nsat: concat(leftResult.nsat, rightResult.nsat),
      };
    }

    case "or_i": {
      const leftResult = computeSatisfaction(node.left, satCtx, ctx);
      const rightResult = computeSatisfaction(node.right, satCtx, ctx);

      // or_i: sat = <1> + sat(X) or <0> + sat(Y)
      // nsat = <1> + nsat(X) or <0> + nsat(Y)
      const one = single(Buffer.from([0x01]), false);
      const zero = single(Buffer.alloc(0), false);

      const sat1 = concat(one, leftResult.sat);
      const sat2 = concat(zero, rightResult.sat);
      const nsat1 = concat(one, leftResult.nsat);
      const nsat2 = concat(zero, rightResult.nsat);

      return {
        sat: choose(sat1, sat2),
        nsat: choose(nsat1, nsat2),
      };
    }

    case "andor": {
      const condResult = computeSatisfaction(node.cond, satCtx, ctx);
      const trueResult = computeSatisfaction(node.ifTrue, satCtx, ctx);
      const falseResult = computeSatisfaction(node.ifFalse, satCtx, ctx);

      // andor: sat = sat(X) + sat(Y) or nsat(X) + sat(Z)
      // nsat = nsat(X) + nsat(Z) (if X fails, Z must fail)
      const sat1 = concat(condResult.sat, trueResult.sat);
      const sat2 = concat(condResult.nsat, falseResult.sat);

      return {
        sat: choose(sat1, sat2),
        nsat: concat(condResult.nsat, falseResult.nsat),
      };
    }

    case "thresh": {
      // thresh(k,X1,...,Xn): exactly k must be satisfied
      // Use dynamic programming to find optimal combination
      const n = node.subs.length;
      const k = node.threshold;

      // Get all sub satisfactions
      const subResults = node.subs.map((sub) =>
        computeSatisfaction(sub, satCtx, ctx)
      );

      // DP: sats[j] = best way to get exactly j satisfactions
      let sats: SatisfactionResult[] = [empty()];

      for (let i = 0; i < n; i++) {
        const newSats: SatisfactionResult[] = [];
        for (let j = 0; j <= i + 1; j++) {
          const candidates: SatisfactionResult[] = [];

          // j satisfactions so far - try adding sat or nsat of sub i
          if (j > 0 && sats[j - 1]) {
            candidates.push(concat(sats[j - 1], subResults[i].sat));
          }
          if (j < i + 1 && sats[j]) {
            candidates.push(concat(sats[j], subResults[i].nsat));
          }

          newSats[j] = candidates.reduce(
            (best, curr) => choose(best, curr),
            unavailable()
          );
        }
        sats = newSats;
      }

      // Dissatisfaction: 0 satisfactions (all nsat)
      const nsat =
        sats[0] ||
        subResults.reduce(
          (acc, r) => concat(acc, r.nsat),
          empty()
        );

      return {
        sat: sats[k] || unavailable(),
        nsat,
      };
    }

    case "multi": {
      // multi(k,K1,...,Kn): <0> <sig1>...<sigk> for sat
      const k = node.threshold;
      const n = node.keys.length;

      // Find available signatures
      const availableSigs: { idx: number; sig: Buffer }[] = [];
      for (let i = 0; i < n; i++) {
        const keyHex = node.keys[i].toString("hex");
        const sig = satCtx.signatures.get(keyHex);
        if (sig) {
          availableSigs.push({ idx: i, sig });
        }
      }

      if (availableSigs.length >= k) {
        // Take first k signatures (in order by key index for non-malleability)
        const selected = availableSigs.slice(0, k).sort((a, b) => a.idx - b.idx);

        // Build witness: <0> <sig1> ... <sigk> (CHECKMULTISIG bug requires dummy)
        const stack: WitnessElement[] = [{ data: Buffer.alloc(0), hasSig: false }];
        let size = 1;
        for (const { sig } of selected) {
          stack.push({ data: sig, hasSig: true });
          size += sig.length + 1;
        }

        return {
          sat: {
            available: Availability.YES,
            stack,
            malleable: false,
            size,
          },
          nsat: {
            available: Availability.YES,
            stack: [
              { data: Buffer.alloc(0), hasSig: false },
              ...Array(k).fill({ data: Buffer.alloc(0), hasSig: false }),
            ],
            malleable: true,
            size: k + 1,
          },
        };
      }

      return {
        sat: unavailable(),
        nsat: {
          available: Availability.YES,
          stack: [
            { data: Buffer.alloc(0), hasSig: false },
            ...Array(k).fill({ data: Buffer.alloc(0), hasSig: false }),
          ],
          malleable: true,
          size: k + 1,
        },
      };
    }

    case "multi_a": {
      // multi_a(k,K1,...,Kn): <sig_n>...<sig_1> (reverse order, signatures or empty)
      const k = node.threshold;
      const n = node.keys.length;

      // Build witness in reverse key order
      const stack: WitnessElement[] = [];
      let sigCount = 0;
      let size = 0;

      for (let i = n - 1; i >= 0; i--) {
        const keyHex = node.keys[i].toString("hex");
        const sig = satCtx.signatures.get(keyHex);

        if (sig && sigCount < k) {
          stack.push({ data: sig, hasSig: true });
          size += sig.length + 1;
          sigCount++;
        } else {
          stack.push({ data: Buffer.alloc(0), hasSig: false });
          size += 1;
        }
      }

      if (sigCount >= k) {
        return {
          sat: {
            available: Availability.YES,
            stack,
            malleable: false,
            size,
          },
          nsat: {
            available: Availability.YES,
            stack: Array(n).fill({ data: Buffer.alloc(0), hasSig: false }),
            malleable: true,
            size: n,
          },
        };
      }

      return {
        sat: unavailable(),
        nsat: {
          available: Availability.YES,
          stack: Array(n).fill({ data: Buffer.alloc(0), hasSig: false }),
          malleable: true,
          size: n,
        },
      };
    }

    case "wrap_a": {
      const innerResult = computeSatisfaction(node.inner, satCtx, ctx);
      // a:X - same satisfaction, different compilation
      return innerResult;
    }

    case "wrap_s": {
      const innerResult = computeSatisfaction(node.inner, satCtx, ctx);
      // s:X - same satisfaction
      return innerResult;
    }

    case "wrap_c": {
      const innerResult = computeSatisfaction(node.inner, satCtx, ctx);
      // c:X - same satisfaction
      return innerResult;
    }

    case "wrap_d": {
      const innerResult = computeSatisfaction(node.inner, satCtx, ctx);
      // d:X - sat = sat(X), nsat = <0>
      return {
        sat: innerResult.sat,
        nsat: single(Buffer.alloc(0), false),
      };
    }

    case "wrap_v": {
      const innerResult = computeSatisfaction(node.inner, satCtx, ctx);
      // v:X - same sat, cannot nsat (type V)
      return {
        sat: innerResult.sat,
        nsat: unavailable(),
      };
    }

    case "wrap_j": {
      const innerResult = computeSatisfaction(node.inner, satCtx, ctx);
      // j:X - sat = sat(X), nsat = <0>
      return {
        sat: innerResult.sat,
        nsat: single(Buffer.alloc(0), false),
      };
    }

    case "wrap_n": {
      const innerResult = computeSatisfaction(node.inner, satCtx, ctx);
      // n:X - same satisfaction
      return innerResult;
    }

    default:
      throw new Error(`Cannot compute satisfaction for: ${(node as MiniscriptNode).type}`);
  }
}

/**
 * Generate the minimal witness for a miniscript.
 */
export function generateWitness(
  node: MiniscriptNode,
  satCtx: SatisfactionContext,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): Buffer[] | null {
  const result = computeSatisfaction(node, satCtx, ctx);

  if (result.sat.available === Availability.NO) {
    return null;
  }

  return result.sat.stack.map((e) => e.data);
}

// =============================================================================
// Analysis
// =============================================================================

/**
 * Analysis result for a miniscript.
 */
export interface MiniscriptAnalysis {
  /** Maximum witness size in bytes */
  maxWitnessSize: number;
  /** Required public keys */
  requiredKeys: Buffer[];
  /** Required hash preimages */
  requiredHashes: Buffer[];
  /** Timelock information */
  timelocks: {
    /** Relative time timelocks (CSV) */
    relativeTime: number[];
    /** Relative height timelocks (CSV) */
    relativeHeight: number[];
    /** Absolute time timelocks (CLTV) */
    absoluteTime: number[];
    /** Absolute height timelocks (CLTV) */
    absoluteHeight: number[];
    /** Whether there's a timelock conflict */
    hasConflict: boolean;
  };
  /** Script size in bytes */
  scriptSize: number;
  /** Whether the script is sane (valid, non-malleable, etc.) */
  isSane: boolean;
  /** Validation issues */
  issues: string[];
}

/**
 * Analyze a miniscript for size, required inputs, and potential issues.
 */
export function analyzeMiniscript(
  node: MiniscriptNode,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): MiniscriptAnalysis {
  const requiredKeys: Buffer[] = [];
  const requiredHashes: Buffer[] = [];
  const timelocks = {
    relativeTime: [] as number[],
    relativeHeight: [] as number[],
    absoluteTime: [] as number[],
    absoluteHeight: [] as number[],
    hasConflict: false,
  };
  const issues: string[] = [];

  // Collect all keys, hashes, and timelocks
  function collect(n: MiniscriptNode): void {
    switch (n.type) {
      case "pk_k":
        requiredKeys.push(n.key);
        break;
      case "pk_h":
        if (n.key) requiredKeys.push(n.key);
        break;
      case "older": {
        const isTime = (n.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG) !== 0;
        if (isTime) {
          timelocks.relativeTime.push(n.sequence);
        } else {
          timelocks.relativeHeight.push(n.sequence);
        }
        break;
      }
      case "after": {
        if (n.locktime >= LOCKTIME_THRESHOLD) {
          timelocks.absoluteTime.push(n.locktime);
        } else {
          timelocks.absoluteHeight.push(n.locktime);
        }
        break;
      }
      case "sha256":
      case "hash256":
        requiredHashes.push(n.hash);
        break;
      case "ripemd160":
      case "hash160":
        requiredHashes.push(n.hash);
        break;
      case "and_v":
      case "and_b":
      case "or_b":
      case "or_c":
      case "or_d":
      case "or_i":
        collect(n.left);
        collect(n.right);
        break;
      case "andor":
        collect(n.cond);
        collect(n.ifTrue);
        collect(n.ifFalse);
        break;
      case "thresh":
        for (const sub of n.subs) {
          collect(sub);
        }
        break;
      case "multi":
      case "multi_a":
        for (const key of n.keys) {
          requiredKeys.push(key);
        }
        break;
      case "wrap_a":
      case "wrap_s":
      case "wrap_c":
      case "wrap_d":
      case "wrap_v":
      case "wrap_j":
      case "wrap_n":
        collect(n.inner);
        break;
    }
  }

  collect(node);

  // Check for timelock conflicts
  const hasTime = timelocks.relativeTime.length > 0 || timelocks.absoluteTime.length > 0;
  const hasHeight = timelocks.relativeHeight.length > 0 || timelocks.absoluteHeight.length > 0;
  timelocks.hasConflict = hasTime && hasHeight;

  if (timelocks.hasConflict) {
    issues.push("Timelock conflict: mixing time and height-based timelocks");
  }

  // Check type validity
  try {
    const type = computeType(node, ctx);

    // Top-level must be type B
    if (type.base !== BaseType.B) {
      issues.push(`Invalid top-level type: expected B, got ${type.base}`);
    }

    // Check properties for sanity
    if (!type.props.m) {
      issues.push("Script is malleable");
    }
    if (!type.props.s) {
      issues.push("Script does not require a signature");
    }
    if (!type.props.k) {
      issues.push("Timelock mixing detected in type properties");
    }
  } catch (e) {
    issues.push(`Type error: ${(e as Error).message}`);
  }

  // Compute script size
  const script = compileScript(node, ctx);
  const scriptSize = script.length;

  // Check script size limits
  const maxSize = ctx === MiniscriptContext.P2WSH
    ? MAX_STANDARD_P2WSH_SCRIPT_SIZE
    : MAX_TAPSCRIPT_SIZE;

  if (scriptSize > maxSize) {
    issues.push(`Script too large: ${scriptSize} > ${maxSize}`);
  }

  // Estimate max witness size (worst case)
  const maxWitnessSize = estimateMaxWitnessSize(node, ctx);

  return {
    maxWitnessSize,
    requiredKeys,
    requiredHashes,
    timelocks,
    scriptSize,
    isSane: issues.length === 0,
    issues,
  };
}

/**
 * Estimate the maximum witness size for a miniscript.
 */
function estimateMaxWitnessSize(
  node: MiniscriptNode,
  ctx: MiniscriptContext
): number {
  // Signature sizes
  const sigSize = ctx === MiniscriptContext.P2WSH ? 73 : 65; // DER vs Schnorr
  const keySize = ctx === MiniscriptContext.P2WSH ? 33 : 32;

  function estimate(n: MiniscriptNode): number {
    switch (n.type) {
      case "just_0":
      case "just_1":
        return 0;
      case "pk_k":
        return sigSize;
      case "pk_h":
        return sigSize + keySize;
      case "older":
      case "after":
        return 0;
      case "sha256":
      case "hash256":
        return 32 + 1; // 32-byte preimage + push opcode
      case "ripemd160":
      case "hash160":
        return 32 + 1; // 32-byte preimage + push opcode (size check is 32)
      case "and_v":
      case "and_b":
        return estimate(n.left) + estimate(n.right);
      case "or_b":
      case "or_c":
      case "or_d":
        return Math.max(estimate(n.left), estimate(n.right)) + estimate(n.left) + estimate(n.right);
      case "or_i":
        return Math.max(estimate(n.left), estimate(n.right)) + 1; // +1 for IF selector
      case "andor":
        return Math.max(
          estimate(n.cond) + estimate(n.ifTrue),
          estimate(n.cond) + estimate(n.ifFalse)
        );
      case "thresh": {
        // All subs contribute, but only threshold are satisfied
        let total = 0;
        for (const sub of n.subs) {
          total += estimate(sub);
        }
        return total;
      }
      case "multi":
        return 1 + n.threshold * sigSize; // dummy + k signatures
      case "multi_a":
        return n.keys.length * sigSize; // n signatures (empty for non-signers)
      case "wrap_a":
      case "wrap_s":
      case "wrap_c":
      case "wrap_d":
      case "wrap_v":
      case "wrap_j":
      case "wrap_n":
        return estimate(n.inner);
      default:
        return 0;
    }
  }

  return estimate(node);
}

// =============================================================================
// String Representation
// =============================================================================

/**
 * Convert a miniscript AST back to string representation.
 */
export function miniscriptToString(node: MiniscriptNode): string {
  switch (node.type) {
    case "just_0":
      return "0";
    case "just_1":
      return "1";
    case "pk_k":
      // Use pk_k notation (pk is sugar for c:pk_k)
      return `pk_k(${node.key.toString("hex")})`;
    case "pk_h":
      // Use pk_h notation (pkh is sugar for c:pk_h)
      if (node.key) {
        return `pk_h(${node.key.toString("hex")})`;
      }
      return `pk_h(${node.keyHash.toString("hex")})`;
    case "older":
      return `older(${node.sequence})`;
    case "after":
      return `after(${node.locktime})`;
    case "sha256":
      return `sha256(${node.hash.toString("hex")})`;
    case "hash256":
      return `hash256(${node.hash.toString("hex")})`;
    case "ripemd160":
      return `ripemd160(${node.hash.toString("hex")})`;
    case "hash160":
      return `hash160(${node.hash.toString("hex")})`;
    case "and_v":
      return `and_v(${miniscriptToString(node.left)},${miniscriptToString(node.right)})`;
    case "and_b":
      return `and_b(${miniscriptToString(node.left)},${miniscriptToString(node.right)})`;
    case "or_b":
      return `or_b(${miniscriptToString(node.left)},${miniscriptToString(node.right)})`;
    case "or_c":
      return `or_c(${miniscriptToString(node.left)},${miniscriptToString(node.right)})`;
    case "or_d":
      return `or_d(${miniscriptToString(node.left)},${miniscriptToString(node.right)})`;
    case "or_i":
      return `or_i(${miniscriptToString(node.left)},${miniscriptToString(node.right)})`;
    case "andor":
      return `andor(${miniscriptToString(node.cond)},${miniscriptToString(node.ifTrue)},${miniscriptToString(node.ifFalse)})`;
    case "thresh": {
      const subs = node.subs.map(miniscriptToString).join(",");
      return `thresh(${node.threshold},${subs})`;
    }
    case "multi": {
      const keys = node.keys.map((k) => k.toString("hex")).join(",");
      return `multi(${node.threshold},${keys})`;
    }
    case "multi_a": {
      const keys = node.keys.map((k) => k.toString("hex")).join(",");
      return `multi_a(${node.threshold},${keys})`;
    }
    case "wrap_a":
      return `a:${miniscriptToString(node.inner)}`;
    case "wrap_s":
      return `s:${miniscriptToString(node.inner)}`;
    case "wrap_c":
      // c:pk_k becomes pk, c:pk_h becomes pkh
      if (node.inner.type === "pk_k") {
        return `pk(${node.inner.key.toString("hex")})`;
      }
      if (node.inner.type === "pk_h") {
        if (node.inner.key) {
          return `pkh(${node.inner.key.toString("hex")})`;
        }
        return `pkh(${node.inner.keyHash.toString("hex")})`;
      }
      return `c:${miniscriptToString(node.inner)}`;
    case "wrap_d":
      return `d:${miniscriptToString(node.inner)}`;
    case "wrap_v":
      return `v:${miniscriptToString(node.inner)}`;
    case "wrap_j":
      return `j:${miniscriptToString(node.inner)}`;
    case "wrap_n":
      return `n:${miniscriptToString(node.inner)}`;
    default:
      throw new Error(`Unknown node type: ${(node as MiniscriptNode).type}`);
  }
}

// =============================================================================
// Type Checking Functions
// =============================================================================

/**
 * Check if a miniscript is valid at the top level.
 */
export function isValidTopLevel(
  node: MiniscriptNode,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): boolean {
  try {
    const type = computeType(node, ctx);
    return type.base === BaseType.B && validateType(type);
  } catch {
    return false;
  }
}

/**
 * Check if a miniscript is sane (valid, non-malleable, requires sig, no timelock mix).
 */
export function isSane(
  node: MiniscriptNode,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): boolean {
  try {
    const type = computeType(node, ctx);

    // Must be top-level valid
    if (type.base !== BaseType.B) return false;

    // Must be non-malleable
    if (!type.props.m) return false;

    // Must require a signature
    if (!type.props.s) return false;

    // Must not have timelock mixing
    if (!type.props.k) return false;

    // Check script size
    const script = compileScript(node, ctx);
    const maxSize = ctx === MiniscriptContext.P2WSH
      ? MAX_STANDARD_P2WSH_SCRIPT_SIZE
      : MAX_TAPSCRIPT_SIZE;
    if (script.length > maxSize) return false;

    return true;
  } catch {
    return false;
  }
}

/**
 * Check if a miniscript requires a signature.
 */
export function needsSignature(
  node: MiniscriptNode,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): boolean {
  try {
    const type = computeType(node, ctx);
    return type.props.s;
  } catch {
    return false;
  }
}

/**
 * Check if a miniscript is non-malleable.
 */
export function isNonMalleable(
  node: MiniscriptNode,
  ctx: MiniscriptContext = MiniscriptContext.P2WSH
): boolean {
  try {
    const type = computeType(node, ctx);
    return type.props.m;
  } catch {
    return false;
  }
}
