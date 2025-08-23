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

print("---- Done ----")
