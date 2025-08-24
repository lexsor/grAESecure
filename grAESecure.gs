//////////////////////////////////////////////////////////
// Script Name: grAESecure
// Author: Lexsor
// Created: 20 AUG 2025
// Version: 0.2
// Purpose: algorithm for AES-256 encryption and decryption
// Location to compile: /opt/crypto/grAESecure
//////////////////////////////////////////////////////////

// ==== grAESecure bootstrap (must come first) ====
// Use AESLIB internally; export via AES256_LIB
AESLIB = {}
AESLIB.PATHS = {} 
AESLIB.BYTES = {} 
AESLIB.MODES = {} 
AESLIB.HASH  = {} 
AESLIB.KEYS  = {} 
AESLIB.AES256 = {}

// Default paths (used by KEYS helpers)
AESLIB.PATHS.base = "/opt/crypto" 
AESLIB.PATHS.mac_key_name = "grAESecure_mac.key" 
AESLIB.PATHS.mac_key_path = AESLIB.PATHS.base + "/" + AESLIB.PATHS.mac_key_name 
AESLIB.PATHS.mac_key_backup = AESLIB.PATHS.base + "/grAESecure_mac.key.bak" 

// -------------------- Small utils --------------------
slice = function(arr, start, end_exclusive)
    out = []
    i = start
    while i < end_exclusive
        out.push(arr[i])
        i = i + 1
    end while
    return out
end function

append_inplace = function(dst, src)
    i = 0
    while i < len(src)
        dst.push(src[i])
        i = i + 1
    end while
    return dst
end function

// Safe append of all elements from src into dst (handles lists and map-like arrays)
AESLIB.BYTES.append_all = function(dst, src)
    i = 0
    while i < len(src)
        v = src[i]
        if v == null then
            v = src[str(i)]
            if v == null then 
                break 
            end if
        end if
        dst.push(v)
        i = i + 1
    end while
end function

AESLIB.BYTES.append_slice = function(dst, src, start, end_exclusive)
    i = start
    while i < end_exclusive and i < len(src)
        dst.push(src[i])
        i = i + 1
    end while
end function

// -------------------- BYTES helpers --------------------
// Build once at load time (keep whatever version you already have)
AESLIB.BYTES._build_charmap = function()
    m = {}
    i = 0
    while i < 256
        c = char(i)   // string of length 1
        m[c] = i      // key is a string, value is number
        i = i + 1
    end while
    return m
end function

// Ensure this exists globally in BYTES
AESLIB.BYTES._charmap = AESLIB.BYTES._build_charmap()

// Clamp helper (keep yours if already present)
AESLIB.BYTES._b = function(x)
    if typeof(x) != "number" then
        return 0
    end if
    n = floor(x)
    if n < 0 then
        return 0
    end if
    if n > 255 then
        return n % 256
    end if
    return n
end function

// Robust 1-char/number → byte
AESLIB.BYTES._ord1 = function(x)
    if x == null then 
        return 0 
    end if

    if typeof(x) == "number" then
        return AESLIB.BYTES._b(x)
    end if

    if typeof(x) == "string" then
        if len(x) == 0 then 
            return 0 
        end if

        // IMPORTANT: if it's exactly one character, use the charmap
        if len(x) == 1 then
            v = AESLIB.BYTES._charmap[x]     // map "0" -> 48, "A" -> 65, etc.
            if v != null then 
                return v 
            else 
                return 0 
            end if
        end if

        // Longer strings like "255" can be parsed numerically
        n = to_int(x)
        if typeof(n) == "number" then
            return AESLIB.BYTES._b(n)
        end if

        return 0
    end if

    return 0
end function

// --- Map→list normalization (handles "0","1",... and {"key":..,"value":..}) ---
AESLIB.BYTES.map_numeric_bytes_to_list = function(m)
    pairs = []
    for kv in m
        keystr = null
        val = null
        if typeof(kv) == "map" then
            keystr = kv["key"]
            val    = kv["value"]
        else
            keystr = kv
            val    = m[keystr]
        end if

        idx = to_int(keystr)
        if typeof(idx) == "number" then
            if typeof(val) != "number" then
                val = AESLIB.BYTES._ord1(val)
            end if
            pairs.push([idx, AESLIB.BYTES._b(val)])
        end if
    end for

    // selection sort by idx
    i = 0
    while i < len(pairs) - 1
        min_i = i
        j = i + 1
        while j < len(pairs)
            if pairs[j][0] < pairs[min_i][0] then
                tmp = pairs[min_i]; pairs[min_i] = pairs[j]; pairs[j] = tmp
            end if
            j = j + 1
        end while
        i = i + 1
    end while

    out = []
    i = 0
    while i < len(pairs)
        out.push(pairs[i][1])
        i = i + 1
    end while
    return out
end function

// Always return a 1-char string for any input, never throws.
AESLIB.BYTES._safe_char = function(v)
    // 1) Coerce to an integer n
    n = 0
    t = typeof(v)

    if t == "number" then
        n = floor(v)
    else
        if t == "string" then
            if len(v) > 0 then
                tn = to_int(v)
                if typeof(tn) == "number" then
                    n = tn
                else
                    // use first character via charmap
                    c = v[0]
                    cv = AESLIB.BYTES._charmap[c]
                    if cv != null then
                        n = cv
                    else
                        n = 0
                    end if
                end if
            else
                n = 0
            end if
        else
            // maps/others → treat as 0
            n = 0
        end if
    end if

    // 2) Clamp to 0..255 using integer-only steps
    while n < 0
        n = n + 256
    end while
    while n >= 256
        n = n - 256
    end while

    // 3) Return a valid single character
    return char(n)
end function

// --- bytes[] or map{"0":..} → string (crash-proof) ---
AESLIB.BYTES.bytes_to_str = function(arr)
    if arr == null then 
        return "" 
    end if
    if typeof(arr) == "string" then 
        return arr 
    end if

    // Normalize non-lists (maps/pairs) to a proper list of bytes
    if typeof(arr) != "list" then
        arr = AESLIB.BYTES.map_numeric_bytes_to_list(arr)
    end if

    s = ""
    i = 0
    while i < len(arr)
        v = arr[i]
        s = s + AESLIB.BYTES._safe_char(v)
        i = i + 1
    end while
    return s
end function

// string -> bytes[]  (pure char→code mapping, 0..255)
AESLIB.BYTES.str_to_bytes = function(s)
    if s == null then 
        return [] 
    end if
    out = []
    i = 0
    while i < len(s)
        c = s[i]                              // single-character string
        v = AESLIB.BYTES._charmap[c]          // 0..255
        if v == null then
            v = 0
        end if
        out.push(v)
        i = i + 1
    end while
    return out
end function

// Random bytes (uses rnd)
AESLIB.BYTES.random_bytes = function(n)
    out = []
    i = 0
    while i < n
        // rnd in [0,1); scale to [0,255]
        out.push( floor(rnd * 256) )
        i = i + 1
    end while
    return out
end function

// Derive 32-byte key from password using repeated md5() (hex string -> bytes)
AESLIB.BYTES.key32_from_password = function(password)
    key = []
    prev = password
    while len(key) < 32
        h = md5(prev) // returns hex string length 32
        hb = AESLIB.BYTES.from_hex(h)
        // append up to remaining bytes
        i = 0
        while i < len(hb) and len(key) < 32
            key.push(hb[i])
            i = i + 1
        end while
        prev = h
    end while
    return key
end function

// Strict bytes equality
AESLIB.BYTES.bytes_eq = function(a, b)
    if a == null or b == null then 
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

// Printable view for debugging (ASCII -> char, others -> \xHH)
AESLIB.BYTES.to_printable = function(arr)
    if arr == null then 
        return "" 
    end if
    // Normalize maps to lists if needed
    if typeof(arr) != "list" then
        arr = AESLIB.BYTES.map_numeric_bytes_to_list(arr)
    end if
    hex = "0123456789abcdef"
    s = ""
    i = 0
    while i < len(arr)
        v = arr[i]
        if typeof(v) != "number" then
            v = AESLIB.BYTES._ord1(v)
        end if
        // clamp 0..255
        while v < 0
            v = v + 256
        end while
        while v >= 256
            v = v - 256
        end while

        // printable ASCII 32..126
        if v >= 32 and v <= 126 then
            s = s + char(v)
        else
            // \xHH
            s = s + "\\x" + hex[floor(v / 16)] + hex[v % 16]
        end if
        i = i + 1
    end while
    return s
end function

// -------------------- HASH helpers (compat) --------------------
// --- HEX helpers (robust, lazy-inited) ---
AESLIB.BYTES._hexmap = null

AESLIB.BYTES._build_hexmap = function()
    m = {}
    // digits
    i = 0
    while i <= 9
        s = str(i)
        m[s] = i
        i = i + 1
    end while
    // lowercase
    m["a"] = 10; m["b"] = 11; m["c"] = 12; m["d"] = 13; m["e"] = 14; m["f"] = 15
    // uppercase
    m["A"] = 10; m["B"] = 11; m["C"] = 12; m["D"] = 13; m["E"] = 14; m["F"] = 15
    return m
end function

AESLIB.BYTES._hx = function(ch)
    if AESLIB.BYTES._hexmap == null then
        AESLIB.BYTES._hexmap = AESLIB.BYTES._build_hexmap()
    end if
    v = AESLIB.BYTES._hexmap[ch]
    if v == null then 
        return -1 
    end if
    return v
end function

// Converts a hex string (optionally with spaces/newlines) to bytes[].
// Returns [] on any invalid input.
AESLIB.BYTES.from_hex = function(hs)
    if hs == null then 
        return [] 
    end if

    // strip whitespace
    clean = ""
    i = 0
    while i < len(hs)
        c = hs[i]
        if c != " " and c != "\t" and c != "\r" and c != "\n" then
            clean = clean + c
        end if
        i = i + 1
    end while

    if (len(clean) % 2) != 0 then 
        return [] 
    end if

    out = []
    i = 0
    while i < len(clean)
        hi = AESLIB.BYTES._hx(clean[i])
        lo = AESLIB.BYTES._hx(clean[i + 1])
        if hi < 0 or lo < 0 then 
            return [] 
        end if
        out.push(hi * 16 + lo)
        i = i + 2
    end while
    return out
end function

// Hex encoder (lowercase)
AESLIB.BYTES.to_hex = function(arr)
    if arr == null then 
        return "" 
    end if
    hex = "0123456789abcdef"
    s = ""
    i = 0
    while i < len(arr)
        b = arr[i]
        if typeof(b) != "number" then
            // fallback if a stray char sneaks in
            b = AESLIB.BYTES._ord1(b)
        end if
        v = AESLIB.BYTES._b(b)
        s = s + hex[floor(v / 16)] + hex[v % 16]
        i = i + 1
    end while
    return s
end function

// MD5 -> bytes[]
AESLIB.HASH.md5_bytes = function(data_bytes)
    // md5() returns a hex string; convert to bytes
    s    = AESLIB.BYTES.bytes_to_str(data_bytes)
    hhex = md5(s)
    return AESLIB.BYTES.from_hex(hhex)  // 16 bytes
end function

AESLIB.HASH.block_size = 64

// HMAC-MD5(key, msg) -> 16-byte tag
AESLIB.BYTES.hmac_md5 = function(key, msg)
    if key == null then 
        key = [] 
    end if
    if msg == null then 
        msg = [] 
    end if
    block_size = 64

    // copy key
    k = []
    i = 0
    while i < len(key)
        k.push(key[i])
        i = i + 1
    end while

    // if key longer than block: hash it
    if len(k) > block_size then
        k = AESLIB.HASH.md5_bytes(k)
    end if

    // right-pad key with zeros to block_size
    i = len(k)
    while i < block_size
        k.push(0)
        i = i + 1
    end while

    // pads: 0x36=54, 0x5c=92
    ipad = []
    opad = []
    i = 0
    while i < block_size
        ipad.push(54)
        opad.push(92)
        i = i + 1
    end while

    // xor pads with key
    i = 0
    while i < block_size
        ipad[i] = ipad[i] ^ k[i]
        opad[i] = opad[i] ^ k[i]
        i = i + 1
    end while

    // inner = MD5(ipad || msg)
    inner = []
    i = 0
    while i < block_size
        inner.push(ipad[i])
        i = i + 1
    end while
    i = 0
    while i < len(msg)
        inner.push(msg[i])
        i = i + 1
    end while
    ih = AESLIB.HASH.md5_bytes(inner)

    // outer = MD5(opad || ih)
    outer = []
    i = 0
    while i < block_size
        outer.push(opad[i])
        i = i + 1
    end while
    i = 0
    while i < len(ih)
        outer.push(ih[i])
        i = i + 1
    end while

    return AESLIB.HASH.md5_bytes(outer)
end function

// -------------------- KEYS: load-or-create MAC key --------------------
AESLIB.KEYS.load_or_create_mac_key = function()
    comp = get_shell.host_computer

    // Ensure PATHS exist even if bootstrap moved
    if not AESLIB.PATHS then 
        AESLIB.PATHS = {} 
    end if
    if not AESLIB.PATHS.base then 
        AESLIB.PATHS.base = "/opt/crypto" 
    end if
    if not AESLIB.PATHS.mac_key_name then 
        AESLIB.PATHS.mac_key_name = "grAESecure_mac.key" 
    end if
    if not AESLIB.PATHS.mac_key_path then 
        AESLIB.PATHS.mac_key_path = AESLIB.PATHS.base + "/" + AESLIB.PATHS.mac_key_name 
    end if
    if not AESLIB.PATHS.mac_key_backup then 
        AESLIB.PATHS.mac_key_backup = AESLIB.PATHS.base + "/grAESecure_mac.key.bak" 
    end if
    
    // 1) If the file already exists and is valid, use it
    f = comp.File(AESLIB.PATHS.mac_key_path)
    if f then
        hex = f.get_content
        b = AESLIB.BYTES.from_hex(hex)
        if b != null and len(b) == 32 then
            return b
        end if
    end if

    // 2) Ensure the file exists (creates parent dirs recursively if needed)
    rc = comp.touch(AESLIB.PATHS.mac_key_path)

    // 3) Generate and persist a fresh 32B key (hex)
    key = AESLIB.BYTES.random_bytes(32)
    hex = AESLIB.BYTES.to_hex(key)

    f2 = comp.File(AESLIB.PATHS.mac_key_path)
    if f2 then
        f2.set_content(hex)
    end if
    return key
end function

// -------------------- KEYS: rotate MAC key (with optional backup) --------------------
AESLIB.KEYS.rotate_mac_key = function(backup_opt)
    comp = get_shell.host_computer

    // Ensure current and backup files exist so File() yields file objects
    comp.touch(AESLIB.PATHS.mac_key_path)
    comp.touch(AESLIB.PATHS.mac_key_backup)

    // Optional backup of current content (even if malformed)
    if backup_opt != 0 then
        cur = comp.File(AESLIB.PATHS.mac_key_path)
        bak = comp.File(AESLIB.PATHS.mac_key_backup)
        if cur and bak then
            cur_hex = cur.get_content
            bak.set_content(cur_hex)
        end if
    end if

    // Write new key
    new_key = AESLIB.BYTES.random_bytes(32)
    new_hex = AESLIB.BYTES.to_hex(new_key)
    nf = comp.File(AESLIB.PATHS.mac_key_path)
    if nf then
        nf.set_content(new_hex)
    end if
    return new_key
end function

// -------------------- PKCS#7 for CBC --------------------
AESLIB.MODES.pkcs7_pad = function(bytes, block)
    rem = len(bytes) % block
    pad = block - rem
    if pad == 0 then 
        pad = block 
    end if
    out = []
    append_inplace(out, bytes)
    i = 0
    while i < pad
        out.push(pad)
        i = i + 1
    end while
    return out
end function

AESLIB.MODES.pkcs7_unpad = function(bytes, block)
    if len(bytes) == 0 then 
        return [] 
    end if
    pad = bytes[len(bytes)-1]
    if pad <= 0 or pad > block then
        // bad pad: return original (or empty)
        return []
    end if
    // check pad consistency
    i = 0
    while i < pad
        if bytes[len(bytes)-1 - i] != pad then
            return []
        end if
        i = i + 1
    end while
    return slice(bytes, 0, len(bytes)-pad)
end function

// -------------------- AES-256 CORE --------------------
A = AESLIB.AES256
A.s_box = null
A.inv_s_box = null
A.sboxes_ready = 0

// GF helpers (decimal only; no hex literals)
A.xtime = function(a)
    a2 = bitwise("&", bitwise("<<", a, 1), 255)
    if bitwise("&", a, 128) != 0 then
        a2 = bitwise("^", a2, 27) // 0x1B
    end if
    return a2
end function

A.gmul = function(a, b)
    p = 0
    i = 0
    while i < 8
        if bitwise("&", b, 1) != 0 then
            p = bitwise("^", p, a)
        end if
        hi = bitwise("&", a, 128)
        a = bitwise("&", bitwise("<<", a, 1), 255)
        if hi != 0 then 
            a = bitwise("^", a, 27) 
        end if
        b = bitwise(">>", b, 1)
        i = i + 1
    end while
    return bitwise("&", p, 255)
end function

// Build S-box and inverse S-box at runtime
A.init_sboxes = function()
    if A.sboxes_ready == 1 then
        return
    end if

    // 8-bit rotate-left
    rol8 = function(x, n)
        left = bitwise("&", bitwise("<<", x, n), 255)
        right = bitwise(">>", x, 8 - n)
        return bitwise("^", left, right)
    end function

    s = []; inv = []
    i = 0
    while i < 256
        s.push(0); inv.push(0)
        i = i + 1
    end while

    p = 1
    q = 1
    while true
        // p = p * 3  (i.e., p ^= xtime(p))
        p = bitwise("^", p, A.xtime(p))

        // q = q / 3 == q * 0xF6 (246)
        q = A.gmul(q, 246)

        // affine transform on multiplicative inverse q
        xformed = bitwise("^",
                    bitwise("^",
                    bitwise("^",
                    bitwise("^",
                        q,
                        rol8(q, 1)),
                        rol8(q, 2)),
                        rol8(q, 3)),
                        rol8(q, 4))
        xformed = bitwise("^", xformed, 99) // 0x63

        s[p] = xformed
        if p == 1 then 
            break 
        end if
    end while
    s[0] = 99

    i = 0
    while i < 256
        inv[s[i]] = i
        i = i + 1
    end while

    A.s_box = s
    A.inv_s_box = inv
    A.sboxes_ready = 1
end function

// Byte-wise transforms
A.sub_bytes = function(st)
    i = 0
    while i < 16
        st[i] = A.s_box[st[i]]
        i = i + 1
    end while
    return st
end function

A.inv_sub_bytes = function(st)
    i = 0
    while i < 16
        st[i] = A.inv_s_box[st[i]]
        i = i + 1
    end while
    return st
end function

A.shift_rows = function(st)
    // row1 left rotate 1
    t = st[1]; st[1]=st[5]; st[5]=st[9]; st[9]=st[13]; st[13]=t
    // row2 left rotate 2
    t0 = st[2]; t1 = st[6]; st[2]=st[10]; st[6]=st[14]; st[10]=t0; st[14]=t1
    // row3 left rotate 3 (right rotate 1)
    t = st[15]; st[15]=st[11]; st[11]=st[7]; st[7]=st[3]; st[3]=t
    return st
end function

A.inv_shift_rows = function(st)
    // inverse of above
    t = st[13]; st[13]=st[9]; st[9]=st[5]; st[5]=st[1]; st[1]=t
    t0 = st[10]; t1 = st[14]; st[10]=st[2]; st[14]=st[6]; st[2]=t0; st[6]=t1
    t = st[3]; st[3]=st[7]; st[7]=st[11]; st[11]=st[15]; st[15]=t
    return st
end function

A.mix_columns = function(st)
    c = 0
    while c < 4
        i0 = 4*c+0; i1 = 4*c+1; i2 = 4*c+2; i3 = 4*c+3
        a0 = st[i0]; a1 = st[i1]; a2 = st[i2]; a3 = st[i3]
        st[i0] = bitwise("^", bitwise("^", A.gmul(a0,2), A.gmul(a1,3)), bitwise("^", a2, a3))
        st[i1] = bitwise("^", bitwise("^", a0, A.gmul(a1,2)), bitwise("^", A.gmul(a2,3), a3))
        st[i2] = bitwise("^", bitwise("^", a0, a1), bitwise("^", A.gmul(a2,2), A.gmul(a3,3)))
        st[i3] = bitwise("^", bitwise("^", A.gmul(a0,3), a1), bitwise("^", a2, A.gmul(a3,2)))
        c = c + 1
    end while
    return st
end function

A.inv_mix_columns = function(st)
    c = 0
    while c < 4
        i0 = 4*c+0; i1 = 4*c+1; i2 = 4*c+2; i3 = 4*c+3
        a0 = st[i0]; a1 = st[i1]; a2 = st[i2]; a3 = st[i3]
        st[i0] = bitwise("^", bitwise("^", A.gmul(a0,14), A.gmul(a1,11)), bitwise("^", A.gmul(a2,13), A.gmul(a3,9)))
        st[i1] = bitwise("^", bitwise("^", A.gmul(a0,9),  A.gmul(a1,14)), bitwise("^", A.gmul(a2,11), A.gmul(a3,13)))
        st[i2] = bitwise("^", bitwise("^", A.gmul(a0,13), A.gmul(a1,9)),  bitwise("^", A.gmul(a2,14), A.gmul(a3,11)))
        st[i3] = bitwise("^", bitwise("^", A.gmul(a0,11), A.gmul(a1,13)), bitwise("^", A.gmul(a2,9),  A.gmul(a3,14)))
        c = c + 1
    end while
    return st
end function

A.add_round_key = function(st, rk)
    i = 0
    while i < 16
        st[i] = bitwise("^", st[i], rk[i])
        i = i + 1
    end while
    return st
end function

// Rcon (first 15) decimal
A.rcon = [1,2,4,8,16,32,64,128,27,54,108,216,171,77,154]

A.rot_word = function(w) // [b0,b1,b2,b3]
    return [w[1], w[2], w[3], w[0]]
end function

A.sub_word = function(w)
    if A.sboxes_ready != 1 then
        A.init_sboxes()
    end if
    return [A.s_box[w[0]], A.s_box[w[1]], A.s_box[w[2]], A.s_box[w[3]]]
end function

A.key_expansion_256 = function(key32)
    if A.sboxes_ready != 1 then
        A.init_sboxes()
    end if
    
    // W: 60 words (4 bytes each)
    W = []
    i = 0
    while i < 8
        W.push([key32[4*i+0], key32[4*i+1], key32[4*i+2], key32[4*i+3]])
        i = i + 1
    end while

    i = 8
    rci = 0
    while i < 60
        temp = W[i-1][:]
        if i % 8 == 0 then
            temp = A.sub_word(A.rot_word(temp))
            temp[0] = bitwise("^", temp[0], A.rcon[rci])
            rci = rci + 1
        else
            if i % 8 == 4 then
            temp = A.sub_word(temp)
            end if
        end if
        wp = W[i-8]
        W.push([ bitwise("^", wp[0], temp[0]),
                 bitwise("^", wp[1], temp[1]),
                 bitwise("^", wp[2], temp[2]),
                 bitwise("^", wp[3], temp[3]) ])
        i = i + 1
    end while

    // flatten 60*4 = 240 bytes
    out = []
    i = 0
    while i < len(W)
        append_inplace(out, W[i])
        i = i + 1
    end while
    return out
end function

A.encrypt_block = function(pt16, key32)
    if len(pt16) != 16 or len(key32) != 32 then 
        return null 
    end if
    if A.sboxes_ready != 1 then
        A.init_sboxes()
    end if

    rk = A.key_expansion_256(key32)
    st = pt16[:]

    // round 0
    st = A.add_round_key(st, slice(rk, 0, 16))

    // rounds 1..13
    r = 1
    while r <= 13
        st = A.sub_bytes(st)
        st = A.shift_rows(st)
        st = A.mix_columns(st)
        st = A.add_round_key(st, slice(rk, 16*r, 16*(r+1)))
        r = r + 1
    end while

    // final (no MixColumns)
    st = A.sub_bytes(st)
    st = A.shift_rows(st)
    st = A.add_round_key(st, slice(rk, 224, 240))
    return st
end function

A.decrypt_block = function(ct16, key32)
    if len(ct16) != 16 or len(key32) != 32 then 
        return null 
    end if
    if A.sboxes_ready != 1 then
        A.init_sboxes()
    end if

    rk = A.key_expansion_256(key32)
    st = ct16[:]

    // inverse final
    st = A.add_round_key(st, slice(rk, 224, 240))
    st = A.inv_shift_rows(st)
    st = A.inv_sub_bytes(st)

    // rounds 13..1
    r = 13
    while r >= 1
        st = A.add_round_key(st, slice(rk, 16*r, 16*(r+1)))
        st = A.inv_mix_columns(st)
        st = A.inv_shift_rows(st)
        st = A.inv_sub_bytes(st)
        r = r - 1
    end while

    // round 0
    st = A.add_round_key(st, slice(rk, 0, 16))
    return st
end function

// -------------------- Modes: CBC & CTR --------------------
M = AESLIB.MODES

M.xor_block = function(a, b)
    out = []
    i = 0
    while i < 16
        out.push(bitwise("^", a[i], b[i]))
        i = i + 1
    end while
    return out
end function

M.cbc_encrypt = function(plain_bytes, key32, iv16)
    if len(iv16) != 16 then 
        return [] 
    end if
    // PKCS#7 pad
    data = AESLIB.MODES.pkcs7_pad(plain_bytes, 16)
    out = []
    prev = iv16[:]
    i = 0
    while i < len(data)
        blk = slice(data, i, i+16)
        x = M.xor_block(blk, prev)
        c = A.encrypt_block(x, key32)
        append_inplace(out, c)
        prev = c
        i = i + 16
    end while
    return out
end function

M.cbc_decrypt = function(cipher_bytes, key32, iv16)
    if len(iv16) != 16 then 
        return [] 
    end if
    out = []
    prev = iv16[:]
    i = 0
    while i < len(cipher_bytes)
        cblk = slice(cipher_bytes, i, i+16)
        x = A.decrypt_block(cblk, key32)
        pblk = M.xor_block(x, prev)
        append_inplace(out, pblk)
        prev = cblk
        i = i + 16
    end while
    // unpad
    return AESLIB.MODES.pkcs7_unpad(out, 16)
end function

// iv || ct || tag  (tag = HMAC-MD5(iv||ct), default tag_len = 16)
AESLIB.MODES.seal_cbc_hmac_md5 = function(plain_bytes, key32_enc, key_mac, iv16_opt, tag_len_opt)
    iv = iv16_opt
    if iv == null then
        iv = AESLIB.BYTES.random_bytes(16)
    end if
    if len(iv) != 16 then
        return []
    end if

    ct = AESLIB.MODES.cbc_encrypt(plain_bytes, key32_enc, iv)

    // m = iv || ct
    m = []
    AESLIB.BYTES.append_all(m, iv)
    AESLIB.BYTES.append_all(m, ct)
    
    tag_full = AESLIB.BYTES.hmac_md5(key_mac, m)

    tlen = tag_len_opt
    if tlen == null then 
        tlen = 16 
    end if      // MD5 = 16
    if tlen < 10 then 
        tlen = 10 
    end if          // minimum sane tag length
    if tlen > len(tag_full) then 
        tlen = len(tag_full) 
    end if

    out = []
    AESLIB.BYTES.append_all(out, iv)
    AESLIB.BYTES.append_all(out, ct)
    AESLIB.BYTES.append_slice(out, tag_full, 0, tlen)
    return out
end function

AESLIB.MODES.open_cbc_hmac_md5 = function(sealed_bytes, key32_enc, key_mac, tag_len_opt)
    if sealed_bytes == null then 
        return [] 
    end if
    if len(sealed_bytes) < 42 then 
        return [] 
    end if   // 16 iv + 16 ct + 10 min tag

    tlen = tag_len_opt
    if tlen == null then 
        tlen = 16 
    end if
    if tlen < 10 then 
        tlen = 10 
    end if
    if tlen > len(sealed_bytes) - 16 then 
        return [] 
    end if

    // split iv, ct, tag
    iv = []
    i = 0
    while i < 16
        iv.push(sealed_bytes[i])
        i = i + 1
    end while

    end_ct = len(sealed_bytes) - tlen
    ct = []
    i = 16
    while i < end_ct
        ct.push(sealed_bytes[i])
        i = i + 1
    end while

    tag = []
    i = end_ct
    while i < len(sealed_bytes)
        tag.push(sealed_bytes[i])
        i = i + 1
    end while

    if (len(ct) % 16) != 0 then 
        return [] 
    end if

    // recompute tag on iv||ct
    m = []
    AESLIB.BYTES.append_all(m, iv)
    AESLIB.BYTES.append_all(m, ct)

    tag2 = AESLIB.BYTES.hmac_md5(key_mac, m)

    // constant-time-ish compare
    if len(tag) != tlen then 
        return [] 
    end if
    diff = 0
    i = 0
    while i < tlen
        diff = bitwise("|", diff, bitwise("^", tag[i], tag2[i]))
        i = i + 1
    end while
    if diff != 0 then 
        return [] 
    end if

    // decrypt on success
    return AESLIB.MODES.cbc_decrypt(ct, key32_enc, iv)
end function

// optional friendly aliases
AESLIB.MODES.seal_cbc_auth = AESLIB.MODES.seal_cbc_hmac_md5

// Sealed CBC: returns iv || ciphertext
AESLIB.MODES.seal_cbc = function(plain_bytes, key32, iv16_opt)
    iv = iv16_opt
    if iv == null then
        iv = AESLIB.BYTES.random_bytes(16)
    end if
    if len(iv) != 16 then
        return [] // invalid IV
    end if

    ct = AESLIB.MODES.cbc_encrypt(plain_bytes, key32, iv)
    // concat iv || ct
    out = iv[:] // copy
    append_inplace(out, ct)
    return out
end function

// Open sealed CBC input (expects iv || ciphertext)
AESLIB.MODES.open_cbc = function(sealed_bytes, key32)
    if sealed_bytes == null then
        return []
    end if
    if len(sealed_bytes) < 32 then
        // need at least 16 IV + 16 CT
        return []
    end if
    if (len(sealed_bytes) - 16) % 16 != 0 then
        // ciphertext must be a multiple of 16
        return []
    end if

    iv  = slice(sealed_bytes, 0, 16)
    ct  = slice(sealed_bytes, 16, len(sealed_bytes))
    pt  = AESLIB.MODES.cbc_decrypt(ct, key32, iv) // includes PKCS#7 unpad
    return pt
end function

// CTR keystream: nonce||counter (16 bytes)
// We’ll treat bytes 12..15 as a uint32 coAunter.
M.ctr_xcrypt = function(bytes, key32, nonce16)
    if len(nonce16) != 16 then 
        return [] 
    end if
    out = []
    counter = 0
    i = 0
    while i < len(bytes)
        // build counter block
        block = nonce16[:]
        c0 = bitwise("&", counter, 255)
        c1 = bitwise("&", bitwise(">>", counter, 8), 255)
        c2 = bitwise("&", bitwise(">>", counter, 16), 255)
        c3 = bitwise("&", bitwise(">>", counter, 24), 255)
        block[12] = c3; block[13] = c2; block[14] = c1; block[15] = c0  // big-endian

        ks = A.encrypt_block(block, key32)
        j = 0
        while j < 16 and (i + j) < len(bytes)
            out.push(bitwise("^", bytes[i+j], ks[j]))
            j = j + 1
        end while

        counter = (counter + 1) % 4294967296
        i = i + 16
    end while
    return out
end function

M.ctr_encrypt = M.ctr_xcrypt
M.ctr_decrypt = M.ctr_xcrypt

AESLIB.MODES.ctr_encrypt = AESLIB.MODES.ctr_xcrypt
AESLIB.MODES.ctr_decrypt = AESLIB.MODES.ctr_xcrypt

// -------------------- Friendly text wrappers --------------------
// CBC: returns hex string by default (easy to store)
AESLIB.encrypt_text_cbc = function(text, password, iv16)
    key32 = AESLIB.BYTES.key32_from_password(password)
    pt    = AESLIB.BYTES.str_to_bytes(text)
    ct    = AESLIB.MODES.cbc_encrypt(pt, key32, iv16)
    return AESLIB.BYTES.to_hex(ct)
end function

AESLIB.decrypt_text_cbc = function(cipher_bytes, password, iv16)
    key32 = AESLIB.BYTES.key32_from_password(password)
    pt    = AESLIB.MODES.cbc_decrypt(cipher_bytes, key32, iv16)
    return AESLIB.BYTES.bytes_to_str(pt)
end function

// CTR: returns hex string by default (no padding used)
AESLIB.encrypt_text_ctr = function(text, password, nonce16)
    key32 = AESLIB.BYTES.key32_from_password(password)
    pt    = AESLIB.BYTES.str_to_bytes(text)
    ct    = AESLIB.MODES.ctr_xcrypt(pt, key32, nonce16)
    return AESLIB.BYTES.to_hex(ct)
end function

AESLIB.decrypt_text_ctr = function(cipher_bytes, password, nonce16)
    key32 = AESLIB.BYTES.key32_from_password(password)
    pt    = AESLIB.MODES.ctr_xcrypt(cipher_bytes, key32, nonce16)
    return AESLIB.BYTES.bytes_to_str(pt)
end function

// ===== CTR compat (probe-safe; no direct key reads) =====
if AESLIB != null then
    if AESLIB.MODES != null then

        // Safe fetch helper (no probing)
        AESLIB._fetch = function(m, key)
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

        // Find any CTR core that's exposed
        _ctr = AESLIB._fetch(AESLIB.MODES, "ctr_encrypt")
        if _ctr == null then
            _ctr = AESLIB._fetch(AESLIB.MODES, "ctr_decrypt")
        end if
        if _ctr == null then
            _ctr = AESLIB._fetch(AESLIB.MODES, "ctr_xcrypt")
        end if

        // If we found one, expose stable names that simply forward
        // NOTE: you MUST set the correct ARITY once to avoid "Too Many Arguments".
        CTR_CORE_ARITY = 0   // set to 1, 2, or 3 to match your build

        if _ctr != null then
            if CTR_CORE_ARITY == 1 then
                AESLIB.MODES.ctr_encrypt = function(data, key32_opt, nonce16_opt)
                    return _ctr(data)
                end function
                AESLIB.MODES.ctr_decrypt = AESLIB.MODES.ctr_encrypt
            else
                if CTR_CORE_ARITY == 2 then
                    AESLIB.MODES.ctr_encrypt = function(data, key32, nonce16_opt)
                        return _ctr(data, key32)
                    end function
                    AESLIB.MODES.ctr_decrypt = AESLIB.MODES.ctr_encrypt
                else
                    if CTR_CORE_ARITY == 3 then
                        AESLIB.MODES.ctr_encrypt = function(data, key32, nonce16)
                            return _ctr(data, key32, nonce16)
                        end function
                        AESLIB.MODES.ctr_decrypt = AESLIB.MODES.ctr_encrypt
                    end if
                end if
            end if
        end if
    end if
end if
// ===== end CTR compat =====

AES256_LIB = AESLIB
// EOF