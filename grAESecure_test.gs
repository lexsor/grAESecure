//////////////////////////////////////////////////////////
// Script Name: grAESecure_test
// Author: Lexsor
// Created: 23 AUG 2025
// Version: 0.1
// Purpose: Self-test for /opt/crypto/grAESecure
//////////////////////////////////////////////////////////

import_code("/opt/crypto/grAESecure")

if not AES256_LIB then
    print("[!!] AES256_LIB not found after import")
    exit("")
end if
AES = AES256_LIB

// Force S-boxes ready before any other tests
AES.AES256.init_sboxes()

pass_fail = function(name, ok)
    if ok then
        print("[OK] " + name)
    else
        print("[!!] " + name + "  <-- investigate")
    end if
end function

arr_eq = function(a, b)
    if len(a) != len(b) then
        return false
    end if
    i = 0
    while i < len(a)
        if a[i] != b[i] then
            return false
        end if
        i = i + 1
    end while
    return true
end function

// 1) BYTES round-trip (avoid \x escapes)
t1 = "GreyHackRocks! []{}"
b1 = AES.BYTES.str_to_bytes(t1)
t1b = AES.BYTES.bytes_to_str(b1)
pass_fail("BYTES round-trip", t1 == t1b)

// If you still want to test non-ASCII bytes, do it like this:
b_raw = [0, 1, 254, 255]
s_raw = AES.BYTES.bytes_to_str(b_raw)
b_back = AES.BYTES.str_to_bytes(s_raw)
pass_fail("BYTES raw round-trip", arr_eq(b_raw, b_back))

// -------------------- 2) S-box inverse property --------------------
AES.AES256.init_sboxes()
ok = true
i = 0
while i < 256
    v = AES.AES256.s_box[i]
    inv = AES.AES256.inv_s_box[v]
    if inv != i then
        ok = false
    end if
    i = i + 1
end while
pass_fail("S-box inverse", ok)

// -------------------- 3) GF xtime/gmul sanity checks --------------------
// Use decimal instead of hex (0x57 == 87)
x_ok = true
if AES.AES256.xtime(87) != AES.AES256.gmul(87, 2) then
    x_ok = false
end if
// 3*x == x ^ 2*x   (in GF(2^8))
tmp2 = AES.AES256.gmul(87, 2)
tmp3 = bitwise("^", 87, tmp2)
if AES.AES256.gmul(87, 3) != tmp3 then
    x_ok = false
end if
pass_fail("GF xtime/gmul sanity", x_ok)

// -------------------- 4) Key expansion size --------------------
key32 = AES.BYTES.key32_from_password("super_secret_password_32bytes_long!")
rk = AES.AES256.key_expansion_256(key32)
pass_fail("KeyExpansion size == 240", len(rk) == 240)

// -------------------- 5) Single-block enc/dec reversibility --------------------
pt16 = AES.BYTES.str_to_bytes("GreyHackRocks!!!")  // exactly 16 bytes
ct16 = AES.AES256.encrypt_block(pt16, key32)
rt16 = AES.AES256.decrypt_block(ct16, key32)
pass_fail("Encrypt/Decrypt single block", arr_eq(pt16, rt16))

// -------------------- 6) CBC padding symmetry --------------------
pad = AES.MODES.pkcs7_pad([1,2,3], 16)
unp = AES.MODES.pkcs7_unpad(pad, 16)
pass_fail("PKCS#7 pad/unpad", arr_eq(unp, [1,2,3]))

// -------------------- 7) CBC enc/dec multi-block --------------------
iv = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,99]
text = "CBC test across multiple blocks ... 1234567890 abcdefghijklmnopqrstuvwxyz"
pt = AES.BYTES.str_to_bytes(text)
ct = AES.MODES.cbc_encrypt(pt, key32, iv)
rt_cb = AES.MODES.cbc_decrypt(ct, key32, iv)
pass_fail("CBC enc/dec", AES.BYTES.bytes_to_str(rt_cb) == text)

// -------------------- 8) CTR enc/dec arbitrary length --------------------
nonce = [9,9,9,9,8,8,8,8,7,7,7,7,0,0,0,1]
ct2 = AES.MODES.ctr_xcrypt(pt, key32, nonce)
rt2 = AES.MODES.ctr_xcrypt(ct2, key32, nonce)
pass_fail("CTR enc/dec", arr_eq(pt, rt2))

// -------------------- 9) Wrapper smoke tests (hex I/O) --------------------
ct_hex = AES.encrypt_text_cbc("Hello CBC", "pw123", iv)
back = AES.decrypt_text_cbc(AES.BYTES.from_hex(ct_hex), "pw123", iv)
pass_fail("CBC wrapper round-trip", back == "Hello CBC")

ct_hex2 = AES.encrypt_text_ctr("Hello CTR (stream)", "pw123", nonce)
back2 = AES.decrypt_text_ctr(AES.BYTES.from_hex(ct_hex2), "pw123", nonce)
pass_fail("CTR wrapper round-trip", back2 == "Hello CTR (stream)")

// -------------------- 10) Sealed CBC (iv||ct) --------------------
msg  = "Sealed CBC round-trip OK"   // <- ASCII only
pt3  = AES.BYTES.str_to_bytes(msg)

sealed = AES.MODES.seal_cbc(pt3, key32, null)
pass_fail("sealed_cbc length >= 32", len(sealed) >= 32 and ((len(sealed) - 16) % 16 == 0))

opened = AES.MODES.open_cbc(sealed, key32)
pass_fail("sealed_cbc open -> plaintext", AES.BYTES.bytes_to_str(opened) == msg)

// deterministic check with fixed IV
fixed_iv = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
sealed2  = AES.MODES.seal_cbc(pt3, key32, fixed_iv)
iv2      = slice(sealed2, 0, 16)
ct2      = slice(sealed2, 16, len(sealed2))
expct    = AES.MODES.cbc_encrypt(pt3, key32, fixed_iv)

pass_fail("sealed_cbc uses iv||ct", arr_eq(iv2, fixed_iv) and arr_eq(ct2, expct))
back2 = AES.MODES.open_cbc(sealed2, key32)
pass_fail("sealed_cbc fixed IV round-trip", AES.BYTES.bytes_to_str(back2) == msg)

// invalid inputs
bad_short = AES.MODES.open_cbc([1,2,3], key32)
pass_fail("open_cbc rejects short", len(bad_short) == 0)

bad_mod = slice(fixed_iv, 0, len(fixed_iv)) // start with 16 bytes
bad_mod.push(1); bad_mod.push(2); bad_mod.push(3); bad_mod.push(4)  // +4 -> not multiple of 16
bad_mod = AES.MODES.open_cbc(bad_mod, key32)
pass_fail("open_cbc rejects non-multiple", len(bad_mod) == 0)

// -------------------- 11) Sealed CBC + Auth --------------------
msgA = "Sealed CBC AUTH OK"
ptA  = AES.BYTES.str_to_bytes(msgA)
kenc = key32                       // reuse your 32B AES key from earlier
kmac = AES.BYTES.random_bytes(32)  // 32B MAC key

sealedA = AES.MODES.seal_cbc_auth(ptA, kenc, kmac, null, 32)
pass_fail("seal_cbc_auth layout", len(sealedA) >= 16 + 16 + 10)

openA = AES.MODES.open_cbc_auth(sealedA, kenc, kmac, 32)
pass_fail("open_cbc_auth -> plaintext", AES.BYTES.bytes_to_str(openA) == msgA)

// tamper test
if len(sealedA) > 40 then
    sealedA[20] = sealedA[20] ^ 1
end if
openTamper = AES.MODES.open_cbc_auth(sealedA, kenc, kmac, 32)
pass_fail("open_cbc_auth rejects tamper", len(openTamper) == 0)

// -------------------- Sealed CBC + HMAC-MD5 --------------------
msgA = "Sealed CBC AUTH OK"
ptA  = AES.BYTES.str_to_bytes(msgA)
kenc = key32                        // reuse the 32B AES key you already set up
// kmac = AES.BYTES.random_bytes(32)   // temp MAC key for tests (we'll replace with loader next)
kmac = AES.KEYS.load_or_create_mac_key()

// Seal with random IV; tag_len = 16 (full MD5)
sealedA = AES.MODES.seal_cbc_hmac_md5(ptA, kenc, kmac, null, 16)
pass_fail("hmac_md5 layout", len(sealedA) >= 16 + 16 + 10 and ((len(sealedA) - 16) % 16 == 0))

// Open and verify plaintext
openA = AES.MODES.open_cbc_hmac_md5(sealedA, kenc, kmac, 16)
pass_fail("hmac_md5 open -> plaintext", AES.BYTES.bytes_to_str(openA) == msgA)

// Deterministic IV test (compare ct with plain CBC encrypt)
fixed_iv = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
sealedB  = AES.MODES.seal_cbc_hmac_md5(ptA, kenc, kmac, fixed_iv, 16)
ivB      = slice(sealedB, 0, 16)
ctB      = slice(sealedB, 16, len(sealedB) - 16)
expctB   = AES.MODES.cbc_encrypt(ptA, kenc, fixed_iv)
eq_ct    = 1
i = 0
while i < len(ctB)
    if ctB[i] != expctB[i] then 
        eq_ct = 0 
    end if
    i = i + 1
end while
eq_iv = 1
i = 0
while i < 16
    if ivB[i] != fixed_iv[i] then 
        eq_iv = 0 
    end if
    i = i + 1
end while
pass_fail("hmac_md5 uses iv||ct", eq_iv == 1 and eq_ct == 1)

// Tamper test (flip a bit in ciphertext region)
if len(sealedA) > 40 then
    sealedA[20] = sealedA[20] ^ 1
end if
openTamper = AES.MODES.open_cbc_hmac_md5(sealedA, kenc, kmac, 16)
pass_fail("hmac_md5 rejects tamper", len(openTamper) == 0)

// Wrong MAC key should fail
kmac2 = AES.BYTES.random_bytes(32)
openWrongKey = AES.MODES.open_cbc_hmac_md5(sealedB, kenc, kmac2, 16)
pass_fail("hmac_md5 wrong key fails", len(openWrongKey) == 0)

// Wrong AES key should fail
kenc_bad = AES.BYTES.random_bytes(32)
openWrongEnc = AES.MODES.open_cbc_hmac_md5(sealedB, kenc_bad, kmac, 16)
pass_fail("hmac_md5 wrong enc key fails", len(openWrongEnc) == 0)

// -------------------- Rotate MAC key: behavior test --------------------
msgR   = "Rotate MAC key test"
ptR    = AES.BYTES.str_to_bytes(msgR)
kencR  = key32                           // reuse your existing 32B AES key
kmac0  = AES.KEYS.load_or_create_mac_key()

// Seal under old MAC key
sealed_old = AES.MODES.seal_cbc_hmac_md5(ptR, kencR, kmac0, null, 16)
ok_old     = AES.MODES.open_cbc_hmac_md5(sealed_old, kencR, kmac0, 16)
pass_fail("pre-rotate opens OK", AES.BYTES.bytes_to_str(ok_old) == msgR)

// Rotate MAC key (with backup=1)
kmac1 = AES.KEYS.rotate_mac_key(1)

// Old sealed blob should now FAIL to open under new key
fail_after_rotate = AES.MODES.open_cbc_hmac_md5(sealed_old, kencR, kmac1, 16)
pass_fail("old blob fails after rotate", len(fail_after_rotate) == 0)

// New seals should verify under the new key
sealed_new = AES.MODES.seal_cbc_hmac_md5(ptR, kencR, kmac1, null, 16)
ok_new     = AES.MODES.open_cbc_hmac_md5(sealed_new, kencR, kmac1, 16)
pass_fail("post-rotate opens OK", AES.BYTES.bytes_to_str(ok_new) == msgR)

print("---- Done ----")
