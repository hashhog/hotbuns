import { describe, expect, test } from "bun:test";
import { BufferReader } from "../wire/serialization";
import {
  deserializeTx,
  sigHashLegacy,
  sigHashLegacyRaw,
  removeCodeSeparators,
  findAndDelete,
  prepareSubscriptForSigning,
} from "./tx";

/**
 * Test vectors from Bitcoin Core: src/test/data/sighash.json
 *
 * Format: [raw_transaction, script, input_index, hashType, expected_hash]
 *
 * These test vectors verify the legacy (pre-segwit) sighash computation,
 * including proper handling of OP_CODESEPARATOR (which should be stripped
 * from the subscript before hashing).
 */
const SIGHASH_TEST_VECTORS: [string, string, number, number, string][] = [
  // Vector with empty subscript
  [
    "907c2bc503ade11cc3b04eb2918b6f547b0630ab569273824748c87ea14b0696526c66ba740200000004ab65ababfd1f9bdd4ef073c7afc4ae00da8a66f429c917a0081ad1e1dabce28d373eab81d8628de802000000096aab5253ab52000052ad042b5f25efb33beec9f3364e8a9139e8439d9d7e26529c3c30b6c3fd89f8684cfd68ea0200000009ab53526500636a52ab599ac2fe02a526ed040000000008535300516352515164370e010000000003006300ab2ec229",
    "",
    2,
    1864164639,
    "31af167a6cf3f9d5f6875caa4d31704ceb0eba078d132b78dab52c3b8997317e",
  ],
  // Vector with simple subscript
  [
    "a0aa3126041621a6dea5b800141aa696daf28408959dfb2df96095db9fa425ad3f427f2f6103000000015360290e9c6063fa26912c2e7fb6a0ad80f1c5fea1771d42f12976092e7a85a4229fdb6e890000000001abc109f6e47688ac0e4682988785744602b8c87228fcef0695085edf19088af1a9db126e93000000000665516aac536affffffff8fe53e0806e12dfd05d67ac68f4768fdbe23fc48ace22a5aa8ba04c96d58e2750300000009ac51abac63ab5153650524aa680455ce7b000000000000499e50030000000008636a00ac526563ac5051ee030000000003abacabd2b6fe000000000003516563910fb6b5",
    "65",
    0,
    -1391424484,
    "48d6a1bd2cd9eec54eb866fc71209418a950402b5d7e52363bfb75c98e141175",
  ],
  // Vector with OP_CODESEPARATOR (0xab) in subscript - should be stripped
  [
    "6e7e9d4b04ce17afa1e8546b627bb8d89a6a7fefd9d892ec8a192d79c2ceafc01694a6a7e7030000000953ac6a51006353636a33bced1544f797f08ceed02f108da22cd24c9e7809a446c61eb3895914508ac91f07053a01000000055163ab516affffffff11dc54eee8f9e4ff0bcf6b1a1a35b1cd10d63389571375501af7444073bcec3c02000000046aab53514a821f0ce3956e235f71e4c69d91abe1e93fb703bd33039ac567249ed339bf0ba0883ef300000000090063ab65000065ac654bec3cc504bcf499020000000005ab6a52abac64eb060100000000076a6a5351650053bbbc130100000000056a6aab53abd6e1380100000000026a51c4e509b8",
    "acab655151",
    0,
    479279909,
    "2a3d95b09237b72034b23f2d2bb29fa32a58ab5c6aa72f6aafdfa178ab1dd01c",
  ],
  // More OP_CODESEPARATOR tests
  [
    "73107cbd025c22ebc8c3e0a47b2a760739216a528de8d4dab5d45cbeb3051cebae73b01ca10200000007ab6353656a636affffffffe26816dffc670841e6a6c8c61c586da401df1261a330a6c6b3dd9f9a0789bc9e000000000800ac6552ac6aac51ffffffff0174a8f0010000000004ac52515100000000",
    "5163ac63635151ac",
    1,
    1190874345,
    "06e328de263a87b09beabe222a21627a6ea5c7f560030da31610c4611f4a46bc",
  ],
  // Negative hashType test
  [
    "e93bbf6902be872933cb987fc26ba0f914fcfc2f6ce555258554dd9939d12032a8536c8802030000000453ac5353eabb6451e074e6fef9de211347d6a45900ea5aaf2636ef7967f565dce66fa451805c5cd10000000003525253ffffffff047dc3e6020000000007516565ac656aabec9eea010000000001633e46e600000000000015080a030000000001ab00000000",
    "5300ac6a53ab6a",
    1,
    -886562767,
    "f03aa4fc5f97e826323d0daa03343ebf8a34ed67a1ce18631f8b88e5c992e798",
  ],
  // Simple vector
  [
    "50818f4c01b464538b1e7e7f5ae4ed96ad23c68c830e78da9a845bc19b5c3b0b20bb82e5e9030000000763526a63655352ffffffff023b3f9c040000000008630051516a6a5163a83caf01000000000553ab65510000000000",
    "6aac",
    0,
    946795545,
    "746306f322de2b4b58ffe7faae83f6a72433c22f88062cdde881d4dd8a5a4e2d",
  ],
  // Subscript with multiple OP_CODESEPARATORs
  [
    "d3b7421e011f4de0f1cea9ba7458bf3486bee722519efab711a963fa8c100970cf7488b7bb0200000003525352dcd61b300148be5d05000000000000000000",
    "535251536aac536a",
    0,
    -1960128125,
    "29aa6d2d752d3310eba20442770ad345b7f6a35f96161ede5f07b33e92053e2a",
  ],
  // Another negative hashType
  [
    "c363a70c01ab174230bbe4afe0c3efa2d7f2feaf179431359adedccf30d1f69efe0c86ed390200000002ab51558648fe0231318b04000000000151662170000000000008ac5300006a63acac00000000",
    "",
    0,
    2146479410,
    "191ab180b0d753763671717d051f138d4866b7cb0d1d4811472e64de595d2c70",
  ],
  // Multiple inputs, specific index
  [
    "8d437a7304d8772210a923fd81187c425fc28c17a5052571501db05c7e89b11448b36618cd02000000026a6340fec14ad2c9298fde1477f1e8325e5747b61b7e2ff2a549f3d132689560ab6c45dd43c3010000000963ac00ac000051516a447ed907a7efffebeb103988bf5f947fc688aab2c6a7914f48238cf92c337fad4a79348102000000085352ac526a5152517436edf2d80e3ef06725227c970a816b25d0b58d2cd3c187a7af2cea66d6b27ba69bf33a0300000007000063ab526553f3f0d6140386815d030000000003ab6300de138f00000000000900525153515265abac1f87040300000000036aac6500000000",
    "51",
    3,
    -315779667,
    "b6632ac53578a741ae8c36d8b69e79f39b89913a2c781cdf1bf47a8c29d997a5",
  ],
  // Empty script, empty subscript
  [
    "a63bc673049c75211aa2c09ecc38e360eaa571435fedd2af1116b5c1fa3d0629c269ecccbf0000000008ac65ab516352ac52ffffffffbf1a76fdda7f451a5f0baff0f9ccd0fe9136444c094bb8c544b1af0fa2774b06010000000463535253ffffffff13d6b7c3ddceef255d680d87181e100864eeb11a5bb6a3528cb0d70d7ee2bbbc02000000056a0052abab951241809623313b198bb520645c15ec96bfcc74a2b0f3db7ad61d455cc32db04afc5cc702000000016309c9ae25014d9473020000000004abab6aac3bb1e803",
    "",
    3,
    -232881718,
    "6e48f3da3a4ac07eb4043a232df9f84e110485d7c7669dd114f679c27d15b97e",
  ],
  // Additional vectors for broader coverage
  [
    "4c565efe04e7d32bac03ae358d63140c1cfe95de15e30c5b84f31bb0b65bb542d637f49e0f010000000551abab536348ae32b31c7d3132030a510a1b1aacf7b7c3f19ce8dc49944ef93e5fa5fe2d356b4a73a00100000009abac635163ac00ab514c8bc57b6b844e04555c0a4f4fb426df139475cd2396ae418bc7015820e852f711519bc202000000086a00510000abac52488ff4aec72cbcfcc98759c58e20a8d2d9725aa4a80f83964e69bc4e793a4ff25cd75dc701000000086a52ac6aac5351532ec6b10802463e0200000000000553005265523e08680100000000002f39a6b0",
    "",
    3,
    70712784,
    "c6076b6a45e6fcfba14d3df47a34f6aadbacfba107e95621d8d7c9c0e40518ed",
  ],
  [
    "1233d5e703403b3b8b4dae84510ddfc126b4838dcb47d3b23df815c0b3a07b55bf3098110e010000000163c5c55528041f480f40cf68a8762d6ed3efe2bd402795d5233e5d94bf5ddee71665144898030000000965525165655151656affffffff6381667e78bb74d0880625993bec0ea3bd41396f2bcccc3cc097b240e5e92d6a01000000096363acac6a63536365ffffffff04610ad60200000000065251ab65ab52e90d680200000000046351516ae30e98010000000008abab52520063656a671856010000000004ac6aac514c84e383",
    "6aabab636300",
    1,
    -114996813,
    "aeb8c5a62e8a0b572c28f2029db32854c0b614dbecef0eaa726abebb42eebb8d",
  ],
  // More negative hashType tests
  [
    "0c69702103b25ceaed43122cc2672de84a3b9aa49872f2a5bb458e19a52f8cc75973abb9f102000000055365656aacffffffff3ffb1cf0f76d9e3397de0942038c856b0ebbea355dc9d8f2b06036e19044b0450100000000ffffffff4b7793f4169617c54b734f2cd905ed65f1ce3d396ecd15b6c426a677186ca0620200000008655263526551006a181a25b703240cce0100000000046352ab53dee22903000000000865526a6a516a51005e121602000000000852ab52ababac655200000000",
    "6a516aab63",
    1,
    -2040012771,
    "a6e6cb69f409ec14e10dd476f39167c29e586e99bfac93a37ed2c230fcc1dbbe",
  ],
  [
    "fd22692802db8ae6ab095aeae3867305a954278f7c076c542f0344b2591789e7e33e4d29f4020000000151ffffffffb9409129cfed9d3226f3b6bab7a2c83f99f48d039100eeb5796f00903b0e5e5e0100000006656552ac63abd226abac0403e649000000000007abab51ac5100ac8035f10000000000095165006a63526a52510d42db030000000007635365ac6a63ab24ef5901000000000453ab6a0000000000",
    "536a52516aac6a",
    1,
    309309168,
    "7ca0f75e6530ec9f80d031fc3513ca4ecd67f20cb38b4dacc6a1d825c3cdbfdb",
  ],
  // Large subscript
  [
    "c2b0b99001acfecf7da736de0ffaef8134a9676811602a6299ba5a2563a23bb09e8cbedf9300000000026300ffffffff042997c50300000000045252536a272437030000000007655353ab6363ac663752030000000002ab6a6d5c900000000000066a6a5265abab00000000",
    "52ac525163515251",
    0,
    -894181723,
    "8b300032a1915a4ac05cea2f7d44c26f2a08d109a71602636f15866563eaafdc",
  ],
  // SIGHASH_SINGLE style tests
  [
    "8edcf5a1014b604e53f0d12fe143cf4284f86dc79a634a9f17d7e9f8725f7beb95e8ffcd2403000000046aabac52ffffffff01c402b5040000000005ab6a63525100000000",
    "6351525251acabab6a",
    0,
    1520147826,
    "2765bbdcd3ebb8b1a316c04656b28d637f80bffbe9b040661481d3dc83eea6d6",
  ],
  [
    "2074bad5011847f14df5ea7b4afd80cd56b02b99634893c6e3d5aaad41ca7c8ee8e5098df003000000026a6affffffff018ad59700000000000900ac656a526551635300000000",
    "65635265",
    0,
    -1804671183,
    "663c999a52288c9999bff36c9da2f8b78d5c61b8347538f76c164ccba9868d0a",
  ],
  // Diverse subscripts with OP_CODESEPARATOR
  [
    "cb3178520136cd294568b83bb2520f78fecc507898f4a2db2674560d72fd69b9858f75b3b502000000066aac00515100ffffffff03ab005a01000000000563526363006e3836030000000001abfbda3200000000000665ab0065006500000000",
    "ab516a0063006a5300",
    0,
    1182109299,
    "2149e79c3f4513da4e4378608e497dcfdfc7f27c21a826868f728abd2b8a637a",
  ],
];

describe("removeCodeSeparators", () => {
  test("removes single OP_CODESEPARATOR", () => {
    const script = Buffer.from([0x51, 0xab, 0x52]); // OP_1, OP_CODESEPARATOR, OP_2
    const result = removeCodeSeparators(script);
    expect(result.equals(Buffer.from([0x51, 0x52]))).toBe(true);
  });

  test("removes multiple OP_CODESEPARATORs", () => {
    const script = Buffer.from([0xab, 0x51, 0xab, 0x52, 0xab]); // Multiple code separators
    const result = removeCodeSeparators(script);
    expect(result.equals(Buffer.from([0x51, 0x52]))).toBe(true);
  });

  test("preserves script without OP_CODESEPARATOR", () => {
    const script = Buffer.from([0x51, 0x52, 0x93]); // OP_1, OP_2, OP_ADD
    const result = removeCodeSeparators(script);
    expect(result.equals(script)).toBe(true);
  });

  test("handles empty script", () => {
    const result = removeCodeSeparators(Buffer.alloc(0));
    expect(result.length).toBe(0);
  });

  test("preserves 0xab inside push data", () => {
    // Push 2 bytes: [0xab, 0xac] - 0xab here is data, not an opcode
    const script = Buffer.from([0x02, 0xab, 0xac, 0x51]);
    const result = removeCodeSeparators(script);
    expect(result.equals(script)).toBe(true);
  });

  test("handles OP_PUSHDATA1 with data containing 0xab", () => {
    // OP_PUSHDATA1, length=3, [0xab, 0xab, 0xab]
    const script = Buffer.from([0x4c, 0x03, 0xab, 0xab, 0xab, 0x51]);
    const result = removeCodeSeparators(script);
    expect(result.equals(script)).toBe(true);
  });

  test("removes OP_CODESEPARATOR but preserves 0xab in push data", () => {
    // OP_1, OP_CODESEPARATOR, PUSH_2, [0xab, 0xac], OP_CODESEPARATOR
    const script = Buffer.from([0x51, 0xab, 0x02, 0xab, 0xac, 0xab]);
    const result = removeCodeSeparators(script);
    // Should become: OP_1, PUSH_2, [0xab, 0xac]
    expect(result.equals(Buffer.from([0x51, 0x02, 0xab, 0xac]))).toBe(true);
  });
});

describe("findAndDelete", () => {
  test("removes exact match", () => {
    const script = Buffer.from([0x51, 0x52, 0x53, 0x54]);
    const needle = Buffer.from([0x52, 0x53]);
    const result = findAndDelete(script, needle);
    expect(result.equals(Buffer.from([0x51, 0x54]))).toBe(true);
  });

  test("removes multiple occurrences", () => {
    const script = Buffer.from([0x51, 0x51, 0x52, 0x51]);
    const needle = Buffer.from([0x51]);
    const result = findAndDelete(script, needle);
    expect(result.equals(Buffer.from([0x52]))).toBe(true);
  });

  test("returns original when no match", () => {
    const script = Buffer.from([0x51, 0x52, 0x53]);
    const needle = Buffer.from([0x54, 0x55]);
    const result = findAndDelete(script, needle);
    expect(result.equals(script)).toBe(true);
  });

  test("handles empty needle", () => {
    const script = Buffer.from([0x51, 0x52]);
    const result = findAndDelete(script, Buffer.alloc(0));
    expect(result.equals(script)).toBe(true);
  });

  test("handles empty script", () => {
    const result = findAndDelete(Buffer.alloc(0), Buffer.from([0x51]));
    expect(result.length).toBe(0);
  });

  test("removes push-encoded signature", () => {
    // Simulate a script containing a signature push: PUSH_3 [sig bytes] OP_CHECKSIG
    const sig = Buffer.from([0xaa, 0xbb, 0xcc]);
    const pushEncodedSig = Buffer.from([0x03, 0xaa, 0xbb, 0xcc]); // Length prefix + sig
    const script = Buffer.from([0x51, 0x03, 0xaa, 0xbb, 0xcc, 0xac]);
    const result = findAndDelete(script, pushEncodedSig);
    expect(result.equals(Buffer.from([0x51, 0xac]))).toBe(true);
  });
});

describe("prepareSubscriptForSigning", () => {
  test("removes both OP_CODESEPARATOR and signature", () => {
    // Script: OP_1, OP_CODESEPARATOR, PUSH_2 [sig], OP_CHECKSIG
    const sig = Buffer.from([0xaa, 0xbb]);
    const script = Buffer.from([0x51, 0xab, 0x02, 0xaa, 0xbb, 0xac]);
    const result = prepareSubscriptForSigning(script, sig);
    // Should remove OP_CODESEPARATOR and the push-encoded sig
    expect(result.equals(Buffer.from([0x51, 0xac]))).toBe(true);
  });

  test("handles undefined signature", () => {
    const script = Buffer.from([0x51, 0xab, 0x52]);
    const result = prepareSubscriptForSigning(script, undefined);
    expect(result.equals(Buffer.from([0x51, 0x52]))).toBe(true);
  });

  test("handles empty signature", () => {
    const script = Buffer.from([0x51, 0xab, 0x52]);
    const result = prepareSubscriptForSigning(script, Buffer.alloc(0));
    expect(result.equals(Buffer.from([0x51, 0x52]))).toBe(true);
  });
});

describe("sigHashLegacy with Bitcoin Core test vectors", () => {
  for (let i = 0; i < SIGHASH_TEST_VECTORS.length; i++) {
    const [rawTxHex, subscriptHex, inputIndex, hashType, expectedHashHex] =
      SIGHASH_TEST_VECTORS[i];

    test(`test vector ${i + 1}: input ${inputIndex}, hashType ${hashType}`, () => {
      // Parse transaction
      const rawTx = Buffer.from(rawTxHex, "hex");
      const reader = new BufferReader(rawTx);
      const tx = deserializeTx(reader);

      // Parse subscript
      const subscript =
        subscriptHex.length > 0 ? Buffer.from(subscriptHex, "hex") : Buffer.alloc(0);

      // Compute sighash
      const sighash = sigHashLegacy(tx, inputIndex, subscript, hashType);

      // Expected hash (Bitcoin Core outputs in big-endian display format,
      // but we compute in internal little-endian)
      const expectedHash = Buffer.from(expectedHashHex, "hex");

      // The test vectors have hash in reversed (display) format
      // Our hash256 returns in internal format, so we need to reverse for comparison
      const sighashReversed = Buffer.from(sighash).reverse();

      expect(sighashReversed.toString("hex")).toBe(expectedHash.toString("hex"));
    });
  }
});

describe("sigHashLegacy edge cases", () => {
  test("SIGHASH_SINGLE with index >= outputs returns uint256(1)", () => {
    // Transaction with 1 output but signing input 1
    const rawTxHex =
      "0100000002" + // version + 2 inputs
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "00000000" + // outpoint 1
      "00" + // empty scriptSig
      "ffffffff" + // sequence
      "0000000000000000000000000000000000000000000000000000000000000002" +
      "00000000" + // outpoint 2
      "00" + // empty scriptSig
      "ffffffff" + // sequence
      "01" + // 1 output
      "0000000000000000" + // value
      "00" + // empty scriptPubKey
      "00000000"; // locktime

    const reader = new BufferReader(Buffer.from(rawTxHex, "hex"));
    const tx = deserializeTx(reader);

    // SIGHASH_SINGLE = 0x03, input index 1, but only 1 output
    const hash = sigHashLegacy(tx, 1, Buffer.alloc(0), 0x03);

    // Should return uint256(1) = 0x0100...00
    const expected = Buffer.alloc(32, 0);
    expected[0] = 1;

    expect(hash.equals(expected)).toBe(true);
  });

  test("handles subscript with only OP_CODESEPARATOR", () => {
    const rawTxHex =
      "0100000001" +
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "00000000" +
      "00" +
      "ffffffff" +
      "01" +
      "0000000000000000" +
      "00" +
      "00000000";

    const reader = new BufferReader(Buffer.from(rawTxHex, "hex"));
    const tx = deserializeTx(reader);

    // Subscript is just OP_CODESEPARATOR - should become empty after stripping
    const subscript = Buffer.from([0xab]);
    const hash = sigHashLegacy(tx, 0, subscript, 0x01);

    expect(hash.length).toBe(32);
  });
});

describe("sigHashLegacyRaw", () => {
  test("does not modify subscript", () => {
    const rawTxHex =
      "0100000001" +
      "0000000000000000000000000000000000000000000000000000000000000001" +
      "00000000" +
      "00" +
      "ffffffff" +
      "01" +
      "0000000000000000" +
      "00" +
      "00000000";

    const reader = new BufferReader(Buffer.from(rawTxHex, "hex"));
    const tx = deserializeTx(reader);

    // Subscript with OP_CODESEPARATOR - sigHashLegacyRaw should NOT strip it
    const subscript = Buffer.from([0x51, 0xab, 0x52]);

    // Compute hash with raw (no stripping)
    const hashRaw = sigHashLegacyRaw(tx, 0, subscript, 0x01);

    // Compute hash with normal (strips OP_CODESEPARATOR)
    const hashNormal = sigHashLegacy(tx, 0, subscript, 0x01);

    // They should be different because sigHashLegacy strips 0xab
    expect(hashRaw.equals(hashNormal)).toBe(false);
  });
});
