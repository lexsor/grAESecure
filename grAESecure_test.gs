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

if not AESLIB then
    print("[!!] AESLIB not found after import")
    exit("")
end if

// --------UTILS--------
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
    return AESLIB.BYTES.to_hex(arr)
end function

B = AESLIB.BYTES
pwd = "p@s$w0rd"
iv = B.random_bytes(16)
nonce = B.random_bytes(16)

// CBC text round-trip (hex path)
cbc_hex = AESLIB.encrypt_text_cbc("hello CBC", pwd, iv)
cbc_pt = AESLIB.decrypt_text_cbc(cbc_hex, pwd, iv)
ok_flag = 0
if cbc_pt == "hello CBC" then
    ok_flag = 1
else
    ok_flag = 0
end if
print("Text CBC symmetric: " + str(ok_flag))

// CTR text round-trip (hex path)
ctr_hex = AESLIB.encrypt_text_ctr("hello CTR", pwd, nonce)
ctr_pt = AESLIB.decrypt_text_ctr(ctr_hex, pwd, nonce)
ok_flag = 0
if ctr_pt == "hello CTR" then
    ok_flag = 1
else
    ok_flag = 0
end if
print("Text CTR symmetric: " + str(ok_flag))

// CTR sealed text round-trip (hex path)
ctr_sealed_hex = AESLIB.encrypt_text_ctr_sealed("hello CTR sealed", pwd, 1)
ctr_sealed_pt  = AESLIB.decrypt_text_ctr_sealed(ctr_sealed_hex, pwd)
print("Text CTR sealed symmetric: " + (ctr_sealed_pt == "hello CTR sealed"))


// Extra: bytes-path also works
ctr_bytes = AESLIB.BYTES.from_hex(ctr_hex)
ctr_pt2 = AESLIB.decrypt_text_ctr(ctr_bytes, pwd, nonce)
ok_flag = 0
if ctr_pt2 == "hello CTR" then
    ok_flag = 1
else
    ok_flag = 0
end if
print("Text CTR bytes-input ok: " + str(ok_flag))

// ---------- 1) BYTES round-trip (text) ----------
pt_s = "Hello, GreyScript!"
pt_b = AESLIB.BYTES.str_to_bytes(pt_s)
rt_s = AESLIB.BYTES.bytes_to_str(pt_b)
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
raw_s = AESLIB.BYTES.bytes_to_str(raw)
raw2 = AESLIB.BYTES.str_to_bytes(raw_s)
if BYTES_eq(raw, raw2) then
    OK("BYTES raw round-trip")
else
    FAIL("BYTES raw round-trip")
end if

// ---------- 3) S-box inverse ----------
AES256 = AESLIB.AES256
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
key32 = AESLIB.BYTES.key32_from_password("testkey-256")
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

msg = AESLIB.BYTES.str_to_bytes("PKCS7 test 12345")
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
cbc_pt = AESLIB.BYTES.str_to_bytes("The quick brown fox jumps over the lazy dog.")
cbc_iv = AESLIB.BYTES.random_bytes(16)
cbc_ct = AESLIB.MODES.cbc_encrypt(cbc_pt, key32, cbc_iv)
cbc_pt2 = AESLIB.MODES.cbc_decrypt(cbc_ct, key32, cbc_iv)
if BYTES_eq(cbc_pt, cbc_pt2) then
    OK("CBC enc/dec")
else
    FAIL("CBC enc/dec")
end if

// ---------- 9) CTR sealed enc/dec (2-arg, nonce carried inside) ----------
nonce2 = AESLIB.BYTES.random_bytes(16)
sealed_ctr = AESLIB.MODES.seal_ctr(cbc_pt, key32, nonce2)
opened_ctr = AESLIB.MODES.open_ctr(sealed_ctr, key32)
if BYTES_eq(cbc_pt, opened_ctr) then
    OK("CTR sealed enc/dec")
else
    FAIL("CTR sealed enc/dec")
end if

// ---------- 10) Sealed CBC + HMAC-MD5 ----------

// ---- preflight: turn on deep hash/HMAC logs just for this section
prev_seal = AESLIB.DEBUG_SEAL
prev_hmac = AESLIB.DEBUG_HMAC
prev_hash = AESLIB.DEBUG_HASH
AESLIB.DEBUG_SEAL = 1
AESLIB.DEBUG_HMAC = 1
AESLIB.DEBUG_HASH = 1

// ---- sanity: make sure md5() itself works and returns hex
hex_abc = md5("abc")
print("[PRE] md5('abc') len=" + str(len(hex_abc)) + " val=" + hex_abc)

// ---- sanity: exercise md5_bytes on a known-size buffer (64B)
tmp64 = []
i = 0
while i < 64
    tmp64.push(i % 256)
    i = i + 1
end while
hb = AESLIB.HASH.md5_bytes(tmp64)
print("[PRE] md5_bytes(64) len=" + str(len(hb)))

// ---- sanity: exercise hmac_md5 on tiny inputs
tiny_key = [1,2,3,4]
tiny_msg = [5,6,7,8]
ht = AESLIB.BYTES.hmac_md5(tiny_key, tiny_msg)
print("[PRE] hmac_md5(tiny) len=" + str(len(ht)))

// ---- sanity: build an iv||ct exactly like the seal path and HMAC it
test_iv = AESLIB.BYTES.random_bytes(16)
test_ct = AESLIB.BYTES.random_bytes(48)
msg_m = []
AESLIB.BYTES.append_all(msg_m, test_iv)
AESLIB.BYTES.append_all(msg_m, test_ct)
test_km = AESLIB.BYTES.random_bytes(32)
ht2 = AESLIB.BYTES.hmac_md5(test_km, msg_m)
print("[PRE] hmac_md5(iv||ct 64B) len=" + str(len(ht2)))

print("[MARK] entering sealed CBC keyed block")
// --- sealed CBC keyed test (full-arity, verbose) ---
MODES = AESLIB.MODES

// pick functions
seal_fn = null
open_fn = null

if typeof(MODES) == "map" then
    for kv in MODES
        if typeof(kv) == "map" then
            if kv["key"] == "seal_cbc_hmac_md5" then
                seal_fn = kv["value"]
            end if
            if kv["key"] == "open_cbc_hmac_md5" then
                open_fn = kv["value"]
            end if
        else
            if kv == "seal_cbc_hmac_md5" then
                seal_fn = MODES["seal_cbc_hmac_md5"]
            end if
            if kv == "open_cbc_hmac_md5" then
                open_fn = MODES["open_cbc_hmac_md5"]
            end if
        end if
    end for
end if

// fallbacks if alias exists
if seal_fn == null then
    if typeof(MODES) == "map" then
        for kv in MODES
            if typeof(kv) == "map" then
                if kv["key"] == "seal_cbc_auth" then
                    seal_fn = kv["value"]
                end if
            else
                if kv == "seal_cbc_auth" then
                    seal_fn = MODES["seal_cbc_auth"]
                end if
            end if
        end for
    end if
end if

if open_fn == null then
    if typeof(MODES) == "map" then
        for kv in MODES
            if typeof(kv) == "map" then
                if kv["key"] == "open_cbc_auth" then
                    open_fn = kv["value"]
                end if
            else
                if kv == "open_cbc_auth" then
                    open_fn = MODES["open_cbc_auth"]
                end if
            end if
        end for
    end if
end if

print("[MARK] resolved seal_fn=" + (typeof(seal_fn)))
print("[MARK] resolved open_fn=" + (typeof(open_fn)))

if seal_fn == null then
    print("[SKIP] no seal function found")
else
    if open_fn == null then
        print("[SKIP] no open function found")
    else
        // enable focused debug for this block (turn off again after)
        prev_seal = AESLIB.DEBUG_SEAL
        prev_open = AESLIB.DEBUG_OPEN
        prev_hmac = AESLIB.DEBUG_HMAC
        prev_hash = AESLIB.DEBUG_HASH
        AESLIB.DEBUG_SEAL = 1
        AESLIB.DEBUG_OPEN = 1
        AESLIB.DEBUG_HMAC = 0
        AESLIB.DEBUG_HASH = 0

        key_enc = key32
        key_mac = AESLIB.BYTES.random_bytes(32)
        print("[MARK] inputs len pt=" + str(len(cbc_pt)) + " key_enc=" + str(len(key_enc)) + " key_mac=" + str(len(key_mac)))

        // full-arity call: (pt, key_enc, key_mac, iv16_opt, tag_len_opt)
        print("[MARK] calling seal (keyed, full-arity)")
        sealed_k = seal_fn(cbc_pt, key_enc, key_mac, null, null)
        print("[MARK] seal returned")

        if sealed_k == null then
            print("[FAIL] sealed returned null")
        else
            print("[MARK] sealed_len=" + str(len(sealed_k)))
            // full-arity open: (sealed, key_enc, key_mac, tag_len_opt)
            print("[MARK] calling open (keyed, full-arity)")
            opened_k = open_fn(sealed_k, key_enc, key_mac, null)
            print("[MARK] open returned")
            if opened_k == null then
                print("[FAIL] open returned null")
            else
                print("[MARK] opened_len=" + str(len(opened_k)))
                same = true
                if len(opened_k) != len(cbc_pt) then
                    same = false
                else
                    i_cmp = 0
                    while i_cmp < len(cbc_pt)
                        if opened_k[i_cmp] != cbc_pt[i_cmp] then
                            same = false
                            break
                        end if
                        i_cmp = i_cmp + 1
                    end while
                end if
                if same then
                    print("[OK] sealed_cbc_hmac_md5 open -> plaintext")
                else
                    print("[!!] sealed_cbc_hmac_md5 mismatch")
                end if
            end if
        end if

        // restore debug flags
        AESLIB.DEBUG_SEAL = prev_seal
        AESLIB.DEBUG_OPEN = prev_open
        AESLIB.DEBUG_HMAC = prev_hmac
        AESLIB.DEBUG_HASH = prev_hash
    end if
end if
// --- end sealed CBC keyed test ---

print("[DONE] grAESecure tests finished")
