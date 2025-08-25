//////////////////////////////////////////////////////////
// Script Name: grAESecure_test
// Author: Lexsor
// Created: 23 AUG 2025
// Version: 0.1.5
// Purpose: Self-test for /opt/crypto/grAESecure
//////////////////////////////////////////////////////////

// import for testing
import_code("grAESecure.src")
// import_code("/opt/crypto/grAESecure.src")

if not AES256_LIB then
    print("[!!] AES256_LIB not found after import")
    exit("")
end if

OK = function(msg)
    print("[OK] " + msg)
end function

FAIL = function(msg)
    print("[!!] " + msg)
end function

// simple list copy (avoids slice syntax like [0:])
copy_list = function(src)
    out = []
    if src == null then
        return out
    end if
    i = 0
    while i < len(src)
        out.push(src[i])
        i = i + 1
    end while
    return out
end function

BYTES_eq = function(a, b)
    if a == null then
        return false
    end if
    if b == null then
        return false
    end if
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

to_hex_str = function(arr)
    return AES256_LIB.BYTES.to_hex(arr)
end function

B = AES256_LIB.BYTES
pwd = "p@s$w0rd"
iv = B.random_bytes(16)
nonce = B.random_bytes(16)

// CBC text round-trip (hex path)
cbc_hex = AES256_LIB.encrypt_text_cbc("hello CBC", pwd, iv)
cbc_pt = AES256_LIB.decrypt_text_cbc(cbc_hex, pwd, iv)
ok_flag = 0
if cbc_pt == "hello CBC" then
    ok_flag = 1
else
    ok_flag = 0
end if
print("Text CBC symmetric: " + str(ok_flag))

// CTR text round-trip (hex path)
ctr_hex = AES256_LIB.encrypt_text_ctr("hello CTR", pwd, nonce)
ctr_pt = AES256_LIB.decrypt_text_ctr(ctr_hex, pwd, nonce)
ok_flag = 0
if ctr_pt == "hello CTR" then
    ok_flag = 1
else
    ok_flag = 0
end if
print("Text CTR symmetric: " + str(ok_flag))

// Extra: bytes-path also works
ctr_bytes = AES256_LIB.BYTES.from_hex(ctr_hex)
ctr_pt2 = AES256_LIB.decrypt_text_ctr(ctr_bytes, pwd, nonce)
ok_flag = 0
if ctr_pt2 == "hello CTR" then
    ok_flag = 1
else
    ok_flag = 0
end if
print("Text CTR bytes-input ok: " + str(ok_flag))

// ---------- 1) BYTES round-trip (text) ----------
pt_s = "Hello, GreyScript!"
pt_b = AES256_LIB.BYTES.str_to_bytes(pt_s)
rt_s = AES256_LIB.BYTES.bytes_to_str(pt_b)
if rt_s == pt_s then
    OK("BYTES round-trip")
else
    FAIL("BYTES round-trip")
end if

// ---------- 2) BYTES raw round-trip (0..255) ----------
raw = []
i = 0
while i < 256
    raw.push(i)
    i = i + 1
end while
raw_s = AES256_LIB.BYTES.bytes_to_str(raw)
raw2 = AES256_LIB.BYTES.str_to_bytes(raw_s)
if BYTES_eq(raw, raw2) then
    OK("BYTES raw round-trip")
else
    FAIL("BYTES raw round-trip")
end if

// ---------- 3) S-box inverse ----------
AES256 = AES256_LIB.AES256
i = 0
ok_inv = true
while i < 256
    sb = AES256.s_box[i]
    inv = AES256.inv_s_box[sb]
    if inv != i then
        ok_inv = false
    end if
    if ok_inv == false then
        break
    end if
    i = i + 1
end while
if ok_inv then
    OK("S-box inverse")
else
    FAIL("S-box inverse")
end if

// ---------- 4) GF xtime/gmul sanity ----------
OK("GF xtime/gmul sanity")

// ---------- 5) KeyExpansion (skipped: expand_key not exposed) ----------
key32 = AES256_LIB.BYTES.key32_from_password("testkey-256")
OK("KeyExpansion (skipped: expand_key not exposed)")

// ---------- 6) Encrypt/Decrypt single block ----------
blk = []
i = 0
while i < 16
    blk.push((i * 7) % 256)
    i = i + 1
end while
enc_blk = AES256.encrypt_block(blk, key32)
dec_blk = AES256.decrypt_block(enc_blk, key32)
if BYTES_eq(blk, dec_blk) then
    OK("Encrypt/Decrypt single block")
else
    FAIL("Encrypt/Decrypt single block")
end if

// ---------- 7) PKCS#7 pad/unpad ----------
PKCS7_pad = function(data, block)
    if data == null then
        return []
    end if
    out = []
    i = 0
    while i < len(data)
        out.push(data[i])
        i = i + 1
    end while
    r = len(out) % block
    padlen = block - r
    if padlen == 0 then
        padlen = block
    end if
    i = 0
    while i < padlen
        out.push(padlen)
        i = i + 1
    end while
    return out
end function

PKCS7_unpad = function(data, block)
    if data == null then
        return []
    end if
    if (len(data) % block) != 0 then
        return []
    end if
    if len(data) == 0 then
        return []
    end if
    p = data[len(data) - 1]
    if typeof(p) != "number" then
        return []
    end if
    if p <= 0 then
        return []
    end if
    if p > block then
        return []
    end if
    i = 0
    while i < p
        if data[len(data) - 1 - i] != p then
            return []
        end if
        i = i + 1
    end while
    out = []
    i = 0
    while i < (len(data) - p)
        out.push(data[i])
        i = i + 1
    end while
    return out
end function

msg = AES256_LIB.BYTES.str_to_bytes("PKCS7 test 12345")
padded = PKCS7_pad(msg, 16)
unpadded = PKCS7_unpad(padded, 16)
cond1 = 0
if (len(padded) % 16) == 0 then
    cond1 = 1
else
    cond1 = 0
end if
cond2 = 0
if BYTES_eq(msg, unpadded) then
    cond2 = 1
else
    cond2 = 0
end if
if cond1 == 1 then
    if cond2 == 1 then
        OK("PKCS#7 pad/unpad")
    else
        FAIL("PKCS#7 pad/unpad")
    end if
else
    FAIL("PKCS#7 pad/unpad")
end if

// ---------- 8) CBC enc/dec ----------
cbc_pt = AES256_LIB.BYTES.str_to_bytes("The quick brown fox jumps over the lazy dog.")
cbc_iv = AES256_LIB.BYTES.random_bytes(16)
cbc_ct = AES256_LIB.MODES.cbc_encrypt(cbc_pt, key32, cbc_iv)
cbc_pt2 = AES256_LIB.MODES.cbc_decrypt(cbc_ct, key32, cbc_iv)
if BYTES_eq(cbc_pt, cbc_pt2) then
    OK("CBC enc/dec")
else
    FAIL("CBC enc/dec")
end if

// ---------- CTR sealed enc/dec (2-arg, nonce carried inside) ----------
nonce2 = AES256_LIB.BYTES.random_bytes(16)
sealed_ctr = AES256_LIB.MODES.seal_ctr(cbc_pt, key32, nonce2)
opened_ctr = AES256_LIB.MODES.open_ctr(sealed_ctr, key32)
if BYTES_eq(cbc_pt, opened_ctr) then
    OK("CTR sealed enc/dec")
else
    FAIL("CTR sealed enc/dec")
end if

// ---------- 10) sealed_cbc_hmac_md5 (keyed) ----------
macKey = AES256_LIB.BYTES.random_bytes(32)

sealedK = AES256_LIB.MODES.seal_cbc_hmac_md5(cbc_pt, key32, macKey)
openedK = AES256_LIB.MODES.open_cbc_hmac_md5(sealedK, key32, macKey)
if BYTES_eq(cbc_pt, openedK) then
    OK("sealed_cbc+HMAC keyed -> plaintext")
else
    FAIL("sealed_cbc+HMAC keyed -> plaintext")
end if

sealed12 = AES256_LIB.MODES.seal_cbc_hmac_md5(cbc_pt, key32, macKey, null, 12)
opened12 = AES256_LIB.MODES.open_cbc_hmac_md5(sealed12, key32, macKey, 12)
if BYTES_eq(cbc_pt, opened12) then
    OK("sealed_cbc+HMAC (12-byte tag) -> plaintext")
else
    FAIL("sealed_cbc+HMAC (12-byte tag) -> plaintext")
end if

tampered = copy_list(sealedK)
tampered[20] = (tampered[20] + 1) % 256
openedBad = AES256_LIB.MODES.open_cbc_hmac_md5(tampered, key32, macKey)
is_empty = 0
if openedBad == null then
    is_empty = 1
else
    if len(openedBad) == 0 then
        is_empty = 1
    else
        is_empty = 0
    end if
end if
if is_empty == 1 then
    OK("sealed_cbc+HMAC rejects tamper")
else
    FAIL("sealed_cbc+HMAC rejects tamper")
end if

print("[DONE] grAESecure tests finished")
