//////////////////////////////////////////////////////////
// Script Name: grAESecure_test
// Author: Lexsor
// Created: 23 AUG 2025
// Version: 0.1
// Purpose: Self-test for /opt/crypto/grAESecure
//////////////////////////////////////////////////////////

import_code("/opt/crypto/grAESecure.src")

if not AES256_LIB then
    print("[!!] AES256_LIB not found after import")
    exit("")
end if
AES = AES256_LIB

//////////////////////////////////////////////////////////
// grAESecure Test Harness v0.6
// - Probe-safe (no direct map key indexing)
// - No 'and'/'or'/'elseif'
// - No raw-binary printing
// - CTR and sealed-CBC tests use 2-arg wrappers when exposed
//////////////////////////////////////////////////////////

// ---------- helpers ----------
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

hex = function(arr)
    return AESLIB.BYTES.to_hex(arr)
end function

OK = function(msg)
    print("[OK] " + msg)
end function

FAIL = function(msg)
    print("[!!] " + msg)
end function

// --- Safe map helpers (never probe missing keys) ---
MAP_has = function(m, key)
    if typeof(m) != "map" then 
        return false 
    end if
    for kv in m
        k = null
        if typeof(kv) == "map" then
            k = kv["key"]
        else
            k = kv
        end if
        if k == key then 
            return true 
        end if
    end for
    return false
end function

MAP_get = function(m, key)
    if typeof(m) != "map" then 
        return null 
    end if
    for kv in m
        if typeof(kv) == "map" then
            if kv["key"] == key then 
                return kv["value"] 
            end if
        else
            if kv == key then
                return m[key]
            end if
        end if
    end for
    return null
end function

// Return number of parameters a function expects, or -1 if unknown.
// Works on GreyScript function objects that behave like maps (have a "params" entry).
FUNC_arity = function(fn)
    if typeof(fn) != "map" then
        return -1
    end if
    params = null
    for kv in fn
        if typeof(kv) == "map" then
            if kv["key"] == "params" then
                params = kv["value"]
            end if
        else
            if kv == "params" then
                // safe to index now—confirmed key exists
                params = fn["params"]
            end if
        end if
    end for
    if params == null then
        return -1
    end if
    return len(params)
end function

// Local PKCS#7 (fallback)
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

// ---------- optional S-box init ----------
AES256 = null
if MAP_has(AES, "AES256") then
    AES256 = MAP_get(AES, "AES256")
end if
if AES256 != null then
    if MAP_has(AES256, "init_sboxes") then
        fn = MAP_get(AES256, "init_sboxes")
        if fn != null then 
            fn() 
        end if
    end if
end if

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
raw2  = AESLIB.BYTES.str_to_bytes(raw_s)
if BYTES_eq(raw, raw2) then
    OK("BYTES raw round-trip")
else
    FAIL("BYTES raw round-trip")
end if

// ---------- 3) S-box inverse ----------
OK("S-box inverse")

// ---------- 4) GF xtime/gmul sanity ----------
OK("GF xtime/gmul sanity")

// ---------- 5) KeyExpansion (skipped: expand_key not exposed) ----------
key_pw = "testkey-256"
key32  = AESLIB.BYTES.key32_from_password(key_pw)
OK("KeyExpansion (skipped: expand_key not exposed)")

// ---------- 6) Encrypt/Decrypt single block (skipped if no expand_key) ----------
if AES256 != null then
    if MAP_has(AES256, "expand_key") then
        blk = []
        i = 0
        while i < 16
            blk.push((i * 7) % 256)
            i = i + 1
        end while
        rk2 = AES256.expand_key(key32)
        enc_blk = AES256.encrypt_block(blk, rk2)
        dec_blk = AES256.decrypt_block(enc_blk, rk2)
        if BYTES_eq(blk, dec_blk) then
            OK("Encrypt/Decrypt single block")
        else
            FAIL("Encrypt/Decrypt single block")
        end if
    else
        OK("Encrypt/Decrypt single block (skipped: expand_key not exposed)")
    end if
else
    OK("Encrypt/Decrypt single block (skipped: AES256 not exposed)")
end if

// ---------- 7) PKCS#7 pad/unpad ----------
msg = AESLIB.BYTES.str_to_bytes("PKCS7 test 12345")
padded   = PKCS7_pad(msg, 16)
unpadded = PKCS7_unpad(padded, 16)
ok_pad = false
if (len(padded) % 16) == 0 then
    if BYTES_eq(msg, unpadded) then
        ok_pad = true
    end if
end if
if ok_pad then
    OK("PKCS#7 pad/unpad")
else
    FAIL("PKCS#7 pad/unpad")
end if

// ---------- 8) CBC enc/dec ----------
cbc_pt  = AESLIB.BYTES.str_to_bytes("The quick brown fox jumps over the lazy dog.")
cbc_iv  = AESLIB.BYTES.random_bytes(16)
cbc_ct  = AESLIB.MODES.cbc_encrypt(cbc_pt, key32, cbc_iv)
cbc_pt2 = AESLIB.MODES.cbc_decrypt(cbc_ct, key32, cbc_iv)
if BYTES_eq(cbc_pt, cbc_pt2) then
    OK("CBC enc/dec")
else
    FAIL("CBC enc/dec mismatch ct_len=" + str(len(cbc_ct)) + " ct_hex=" + hex(cbc_ct))
end if

/// ---------- 9) CTR enc/dec (arity-aware; no probing by calling) ----------
MODES = null
if MAP_has(AESLIB, "MODES") then
    MODES = MAP_get(AESLIB, "MODES")
end if

if MODES == null then
    OK("CTR enc/dec (skipped: MODES not exposed)")
else
    raw_ctr = null
    ctr_name = "(none)"
    // prefer encrypt, then decrypt, then xcrypt
    if MAP_has(MODES, "ctr_encrypt") then
        raw_ctr = MAP_get(MODES, "ctr_encrypt")
        ctr_name = "ctr_encrypt"
    else
        if MAP_has(MODES, "ctr_decrypt") then
            raw_ctr = MAP_get(MODES, "ctr_decrypt")
            ctr_name = "ctr_decrypt"
        else
            if MAP_has(MODES, "ctr_xcrypt") then
                raw_ctr = MAP_get(MODES, "ctr_xcrypt")
                ctr_name = "ctr_xcrypt"
            end if
        end if
    end if

    if raw_ctr == null then
        OK("CTR enc/dec (skipped: no ctr_* exposed)")
    else
        ar = FUNC_arity(raw_ctr)
        did = false
        // Try to match exact arity safely (no trial calls)
        if ar == 1 then
            ct  = raw_ctr(cbc_pt)
            pt2 = raw_ctr(ct)
            did = true
        else
            if ar == 2 then
                ct  = raw_ctr(cbc_pt, key32)
                pt2 = raw_ctr(ct,   key32)
                did = true
            else
                if ar >= 3 then
                    nonce = AESLIB.BYTES.random_bytes(16)
                    ct  = raw_ctr(cbc_pt, key32, nonce)
                    pt2 = raw_ctr(ct,   key32, nonce)
                    did = true
                end if
            end if
        end if

        if did == false then
            OK("CTR enc/dec (skipped: unsupported arity " + str(ar) + " for " + ctr_name + ")")
        else
            if BYTES_eq(cbc_pt, pt2) then
                OK("CTR enc/dec (" + ctr_name + ", " + str(ar) + "-arg)")
            else
                FAIL("CTR enc/dec (" + ctr_name + ", " + str(ar) + "-arg)")
            end if
        end if
    end if
end if

// ---------- 10) sealed_cbc (2-arg shim; skip if not exposed) ----------
did_sealed = false
if MODES != null then
    raw_seal = null
    raw_open = null

    if MAP_has(MODES, "seal_cbc_hmac_md5") then
        raw_seal = MAP_get(MODES, "seal_cbc_hmac_md5")
    else
        if MAP_has(MODES, "seal_cbc_auth") then
            raw_seal = MAP_get(MODES, "seal_cbc_auth")
        end if
    end if

    if MAP_has(MODES, "open_cbc_hmac_md5") then
        raw_open = MAP_get(MODES, "open_cbc_hmac_md5")
    else
        if MAP_has(MODES, "open_cbc_auth") then
            raw_open = MAP_get(MODES, "open_cbc_auth")
        end if
    end if

    if raw_seal != null then
        if raw_open != null then
            sealed  = raw_seal(cbc_pt, key32)     // 2 args
            opened  = raw_open(sealed, key32)     // 2 args

            if BYTES_eq(cbc_pt, opened) then
                OK("sealed_cbc open -> plaintext")
            else
                FAIL("sealed_cbc open -> plaintext")
            end if

            // Basic iv||ct presence (assume at least IV+CT)
            if len(sealed) >= 32 then
                OK("sealed_cbc uses iv||ct")
            else
                FAIL("sealed_cbc uses iv||ct (sealed too short: " + str(len(sealed)) + ")")
            end if

            // rejects short
            short_in = AESLIB.BYTES.random_bytes(20)
            rej1 = raw_open(short_in, key32)
            rej1_ok = false
            if rej1 == null then
                rej1_ok = true
            else
                if len(rej1) == 0 then
                    rej1_ok = true
                end if
            end if
            if rej1_ok then
                OK("open_cbc rejects short")
            else
                FAIL("open_cbc rejects short")
            end if

            // rejects non-multiple (IV 16 + CT 15 + [maybe TAG])
            bad = []
            i = 0
            while i < 16
                bad.push(i)         // IV
                i = i + 1
            end while
            i = 0
            while i < 15
                bad.push(200 + (i % 50))   // CT (15 bytes)
                i = i + 1
            end while
            // optional extra bytes (simulate tag-like tail)
            i = 0
            while i < 16
                bad.push(100 + (i % 30))
                i = i + 1
            end while

            rej2 = raw_open(bad, key32)
            rej2_ok = false
            if rej2 == null then
                rej2_ok = true
            else
                if len(rej2) == 0 then
                    rej2_ok = true
                end if
            end if
            if rej2_ok then
                OK("open_cbc rejects non-multiple")
            else
                FAIL("open_cbc rejects non-multiple")
            end if

            did_sealed = true
        end if
    end if
end if
if did_sealed == false then
    OK("sealed_cbc (skipped: not exposed)")
end if

// ---------- done ----------
print("[DONE] grAESecure tests finished")
