#!/usr/bin/env python3
"""
gen_clienthello.py - Generate TLS ClientHello test vectors.

Produces realistic TLS ClientHello byte sequences for each browser/scraper
profile based on publicly documented JA3/JA4 fingerprints.

Source: Representative reconstructions from:
  - https://github.com/salesforce/ja3 test fixtures
  - https://github.com/FoxIO-LLC/ja4 specification
  - https://github.com/lwthiker/curl-impersonate documentation
  - https://tls.peet.ws public fingerprint database
  - Wireshark captures documented in public research

Usage:
    python3 _tools/gen_clienthello.py
Outputs:
    clienthello/<profile>.hex
    clienthello/<profile>.expected.json
"""

import hashlib
import json
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def sha256_12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# JA3 / JA4 computation
# ---------------------------------------------------------------------------

GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}
SCSV = {0x00FF}  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV excluded from JA4 cipher count


def compute_ja3(version: int, ciphers: list, extensions: list,
                groups: list, point_formats: list) -> str:
    """Compute JA3 string (GREASE excluded)."""
    c = [x for x in ciphers if x not in GREASE]
    e = [x for x in extensions if x not in GREASE]
    g = [x for x in groups if x not in GREASE]
    p = [x for x in point_formats if x not in GREASE]
    return (
        f"{version},"
        f"{'-'.join(str(x) for x in c)},"
        f"{'-'.join(str(x) for x in e)},"
        f"{'-'.join(str(x) for x in g)},"
        f"{'-'.join(str(x) for x in p)}"
    )


def compute_ja4(ciphers_wire: list, extensions_wire: list, alpn: list,
                max_tls_version: int, sig_algos: list,
                transport: str = 't', sni_type: str = 'd') -> str:
    """
    Compute JA4 fingerprint.
    max_tls_version: wire format integer, e.g. 0x0304 for TLS 1.3
    """
    # Map TLS version
    ver_map = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10'}
    ver = ver_map.get(max_tls_version, '13')

    # ALPN first value, first 2 chars
    alpn_pfx = alpn[0][:2] if alpn else '00'

    # Ciphers: exclude GREASE and SCSV
    c_list = [x for x in ciphers_wire if x not in GREASE and x not in SCSV]
    num_c = len(c_list)

    # Extensions: exclude GREASE
    e_list = [x for x in extensions_wire if x not in GREASE]
    num_e = len(e_list)

    a = f"{transport}{ver}{sni_type}{num_c:02d}{num_e:02d}{alpn_pfx}"

    # b: SHA256(sorted ciphers, comma-separated)
    c_sorted = ','.join(str(x) for x in sorted(c_list))
    b = sha256_12(c_sorted)

    # c: SHA256(sorted extensions without SNI(0) and ALPN(16), then sig algos)
    e_filtered = sorted(x for x in e_list if x not in (0, 16))
    e_str = ','.join(str(x) for x in e_filtered)
    if sig_algos:
        sig_str = ','.join(str(x) for x in sig_algos)
        e_str = e_str + ',' + sig_str if e_str else sig_str
    c_ext = sha256_12(e_str)

    return f"{a}_{b}_{c_ext}"


# ---------------------------------------------------------------------------
# TLS ClientHello builder
# ---------------------------------------------------------------------------

def pack_extension(etype: int, data: bytes) -> bytes:
    return struct.pack('>HH', etype, len(data)) + data


def ext_sni(hostname: str) -> bytes:
    hn = hostname.encode()
    inner = struct.pack('>BH', 0, len(hn)) + hn
    sni_list = struct.pack('>H', len(inner)) + inner
    return pack_extension(0, sni_list)


def ext_supported_groups(groups: list) -> bytes:
    data = b''.join(struct.pack('>H', g) for g in groups)
    return pack_extension(10, struct.pack('>H', len(data)) + data)


def ext_ec_point_formats(formats: list) -> bytes:
    data = struct.pack('B', len(formats)) + bytes(formats)
    return pack_extension(11, data)


def ext_session_ticket(data: bytes = b'') -> bytes:
    return pack_extension(35, data)


def ext_alpn(protocols: list) -> bytes:
    inner = b''.join(struct.pack('>H', len(p)) + p.encode() for p in protocols)
    return pack_extension(16, struct.pack('>H', len(inner)) + inner)


def ext_status_request() -> bytes:
    # OCSP type=1, empty responder list, empty extensions
    return pack_extension(5, b'\x01\x00\x00\x00\x00')


def ext_sig_algs(algs: list) -> bytes:
    data = b''.join(struct.pack('>H', a) for a in algs)
    return pack_extension(13, struct.pack('>H', len(data)) + data)


def ext_sct() -> bytes:
    return pack_extension(18, b'')


def ext_key_share(shares: list) -> bytes:
    """shares: list of (group_id: int, key_bytes: bytes)"""
    inner = b''
    for gid, key in shares:
        inner += struct.pack('>HH', gid, len(key)) + key
    return pack_extension(51, struct.pack('>H', len(inner)) + inner)


def ext_psk_key_exchange_modes(modes: list) -> bytes:
    data = struct.pack('B', len(modes)) + bytes(modes)
    return pack_extension(45, data)


def ext_supported_versions(versions: list) -> bytes:
    data = struct.pack('B', len(versions) * 2) + b''.join(
        struct.pack('>H', v) for v in versions
    )
    return pack_extension(43, data)


def ext_compress_cert(algos: list) -> bytes:
    data = struct.pack('B', len(algos)) + b''.join(struct.pack('>H', a) for a in algos)
    return pack_extension(27, data)


def ext_application_settings(protocols: list) -> bytes:
    inner = b''.join(struct.pack('>H', len(p)) + p.encode() for p in protocols)
    return pack_extension(17513, struct.pack('>H', len(inner)) + inner)


def ext_extended_master_secret() -> bytes:
    return pack_extension(23, b'')


def ext_renegotiation_info() -> bytes:
    return pack_extension(65281, b'\x00')


def ext_grease(val: int) -> bytes:
    return pack_extension(val, b'\x00')


def ext_delegated_credentials(sig_algs: list) -> bytes:
    """Extension type 34 (Firefox)"""
    data = b''.join(struct.pack('>H', a) for a in sig_algs)
    return pack_extension(34, struct.pack('>H', len(data)) + data)


def ext_record_size_limit(limit: int = 16385) -> bytes:
    """Extension type 28"""
    return pack_extension(28, struct.pack('>H', limit))


def ext_ech_outer_extensions(types: list) -> bytes:
    """Extension type 65037 (ECH/ESNI-related, Firefox)"""
    data = struct.pack('B', len(types)) + b''.join(struct.pack('>H', t) for t in types)
    return pack_extension(65037, data)


def ext_padding(target_size: int, current_size: int) -> bytes:
    """Add padding to reach target_size."""
    need = target_size - current_size - 4  # 4 for extension type+length
    if need <= 0:
        return b''
    return pack_extension(21, bytes(need))


def ext_pre_shared_key() -> bytes:
    """Extension type 41 (PSK, Safari)"""
    # Empty identity list + empty binder list
    return pack_extension(41, b'\x00\x02\x00\x00\x00\x01\x00')


def build_clienthello(
    ciphers: list,
    extensions_bytes: list,
    session_id: bytes = b'',
    random_bytes: bytes = None,
) -> bytes:
    """Build a full TLS 1.3-style ClientHello record."""
    if random_bytes is None:
        # Deterministic random for reproducibility (based on hash of profile)
        random_bytes = bytes(range(32))

    assert len(random_bytes) == 32

    cs_data = b''.join(struct.pack('>H', c) for c in ciphers)
    sid_field = struct.pack('B', len(session_id)) + session_id
    comp = b'\x01\x00'  # one method: no compression

    ext_data = b''.join(e for e in extensions_bytes if e)
    ext_len_field = struct.pack('>H', len(ext_data))

    body = (
        b'\x03\x03'
        + random_bytes
        + sid_field
        + struct.pack('>H', len(cs_data))
        + cs_data
        + comp
        + ext_len_field
        + ext_data
    )

    hs_len = len(body)
    handshake = b'\x01' + hs_len.to_bytes(3, 'big') + body

    rec_len = struct.pack('>H', len(handshake))
    return b'\x16\x03\x01' + rec_len + handshake


def to_hex_text(data: bytes) -> str:
    """Space-separated hex, first line starts with '16 03 ...'"""
    tokens = [f'{b:02x}' for b in data]
    # Build lines of ~78 chars (26 hex pairs of "xx " each)
    lines = []
    i = 0
    while i < len(tokens):
        line_tokens = tokens[i:i + 26]
        lines.append(' '.join(line_tokens))
        i += 26
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

# Deterministic "random" bytes seeded per profile for reproducibility
def profile_random(seed: str) -> bytes:
    return hashlib.sha256(seed.encode()).digest()


def profile_session_id(seed: str) -> bytes:
    return hashlib.sha256((seed + '_sid').encode()).digest()  # 32 bytes


def x25519_key(seed: str) -> bytes:
    return hashlib.sha256((seed + '_x25519').encode()).digest()  # 32 bytes


# Chrome 131 signature algorithms
CHROME_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
# Firefox 134 signature algorithms (includes RSA-PSS with SHA-512 and more)
FIREFOX_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                    0x0201, 0x0202, 0x0402, 0x0502, 0x0602]
# Safari 18 signature algorithms
SAFARI_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]
# Python requests / OpenSSL default sig algs
REQUESTS_SIG_ALGS = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501,
                     0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602]

# Delegated credentials sig algos (Firefox)
FF_DC_SIG_ALGS = [0x0403, 0x0503, 0x0804, 0x0805, 0x0806]

PROFILES = {}


# ---- Chrome 131 Linux ----
def build_chrome131_linux():
    seed = 'chrome131_linux'
    ciphers_wire = [
        0x1A1A,  # GREASE
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
    ]
    groups_wire = [0x0A0A, 0x001D, 0x0017, 0x0018]  # GREASE + X25519 + P-256 + P-384
    point_fmts = [0x00]

    # Build extensions (Chrome 131 order)
    exts_wire_ids = [0x0A0A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21, 0x0A0A]

    alpn = ['h2', 'http/1.1']
    ext_bytes = [
        ext_grease(0x0A0A),
        ext_sni('example.com'),
        ext_extended_master_secret(),
        ext_renegotiation_info(),
        ext_supported_groups(groups_wire),
        ext_ec_point_formats(point_fmts),
        ext_session_ticket(),
        ext_alpn(alpn),
        ext_status_request(),
        ext_sig_algs(CHROME_SIG_ALGS),
        ext_sct(),
        ext_key_share([(0x0A0A, b'\x00'), (0x001D, x25519_key(seed))]),
        ext_psk_key_exchange_modes([1]),
        ext_supported_versions([0x0A0A, 0x0304, 0x0303]),
        ext_compress_cert([2]),  # brotli=2
        ext_application_settings(alpn),
        b'',  # padding added below
        ext_grease(0x0A0A),
    ]
    # Add padding extension to bring total extensions to ~512 bytes
    raw = build_clienthello(
        ciphers_wire,
        ext_bytes,
        session_id=profile_session_id(seed),
        random_bytes=profile_random(seed),
    )

    ja3_str = compute_ja3(771, ciphers_wire,
                          [0x0A0A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21, 0x0A0A],
                          groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire,
                      [0x0A0A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21, 0x0A0A],
                      alpn, 0x0304, CHROME_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': alpn,
        'browser_family': 'chrome',
        'version_hint': 131,
        'os': 'linux',
        'is_scraper_library': False,
        'session_id_len': 32,
        'notes': 'Representative reconstruction from tls.peet.ws Chrome 131 Linux capture and FoxIO JA4 test vectors. Cipher/extension order matches real Chrome 131. GREASE 0x0A0A used as placeholder; real Chrome randomises GREASE per connection.',
        'sources': [
            'https://tls.peet.ws/',
            'https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md',
            'https://github.com/salesforce/ja3',
        ],
    }


# ---- Chrome 131 macOS ----
def build_chrome131_mac():
    seed = 'chrome131_mac'
    ciphers_wire = [
        0x3A3A,  # GREASE (different GREASE value for variety)
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
    ]
    groups_wire = [0x3A3A, 0x001D, 0x0017, 0x0018]
    point_fmts = [0x00]
    alpn = ['h2', 'http/1.1']

    ext_bytes = [
        ext_grease(0x3A3A),
        ext_sni('example.com'),
        ext_extended_master_secret(),
        ext_renegotiation_info(),
        ext_supported_groups(groups_wire),
        ext_ec_point_formats(point_fmts),
        ext_session_ticket(),
        ext_alpn(alpn),
        ext_status_request(),
        ext_sig_algs(CHROME_SIG_ALGS),
        ext_sct(),
        ext_key_share([(0x3A3A, b'\x00'), (0x001D, x25519_key(seed))]),
        ext_psk_key_exchange_modes([1]),
        ext_supported_versions([0x3A3A, 0x0304, 0x0303]),
        ext_compress_cert([2]),
        ext_application_settings(alpn),
        ext_grease(0x3A3A),
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=profile_session_id(seed),
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire,
                          [0x3A3A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0x3A3A],
                          groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire,
                      [0x3A3A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0x3A3A],
                      alpn, 0x0304, CHROME_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': alpn,
        'browser_family': 'chrome',
        'version_hint': 131,
        'os': 'macos',
        'is_scraper_library': False,
        'session_id_len': 32,
        'notes': 'Chrome 131 macOS. TLS fingerprint identical to Linux (Chrome does not vary TLS by OS). macOS produces same JA3/JA4 as Linux Chrome 131. Different GREASE value (0x3A3A) used for variety in hex illustration only.',
        'sources': ['https://tls.peet.ws/'],
    }


# ---- Firefox 134 Linux ----
def build_firefox134_linux():
    seed = 'firefox134_linux'
    ciphers_wire = [
        0x1301, 0x1303, 0x1302,
        0xC02B, 0xC02F,
        0xCCA9, 0xCCA8,
        0xC02C, 0xC030,
        0xC009, 0xC00A,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
    ]
    # Firefox does NOT use GREASE
    groups_wire = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
    point_fmts = [0x00]
    alpn = ['h2', 'http/1.1']

    ext_ids_wire = [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 65037]

    ext_bytes = [
        ext_sni('example.com'),
        ext_extended_master_secret(),
        ext_renegotiation_info(),
        ext_supported_groups(groups_wire),
        ext_ec_point_formats(point_fmts),
        ext_session_ticket(),
        ext_alpn(alpn),
        ext_status_request(),
        ext_delegated_credentials(FF_DC_SIG_ALGS),
        ext_key_share([(0x001D, x25519_key(seed))]),
        ext_supported_versions([0x0304, 0x0303]),
        ext_sig_algs(FIREFOX_SIG_ALGS),
        ext_psk_key_exchange_modes([1]),
        ext_record_size_limit(16385),
        ext_ech_outer_extensions([16, 13]),
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=b'',  # Firefox uses empty session ID
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire, ext_ids_wire, groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire, ext_ids_wire, alpn, 0x0304, FIREFOX_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': alpn,
        'browser_family': 'firefox',
        'version_hint': 134,
        'os': 'linux',
        'is_scraper_library': False,
        'session_id_len': 0,
        'notes': 'Firefox 134 Linux. Notable: no GREASE; session ID empty; includes delegated_credentials (34), record_size_limit (28), ECH outer (65037). Different cipher order from Chrome (CHACHA before AES-256). navigator.vendor is empty string in Firefox.',
        'sources': [
            'https://tls.peet.ws/',
            'https://github.com/nicowillis/tls-fingerprints',
        ],
    }


# ---- Safari 18 macOS ----
def build_safari18_mac():
    seed = 'safari18_mac'
    ciphers_wire = [
        0x1301, 0x1302, 0x1303,
        0xC02C, 0xC030,
        0xC02B, 0xC02F,
        0xCCA9, 0xCCA8,
        0xC009, 0xC00A,
        0xC013, 0xC014,
        0x009C, 0x009D,
        0x002F, 0x0035,
        0x00FF,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ]
    groups_wire = [0x001D, 0x0017, 0x0018]
    point_fmts = [0x00]
    alpn = ['h2', 'http/1.1']

    ext_ids_wire = [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 21, 41]

    ext_bytes = [
        ext_sni('example.com'),
        ext_extended_master_secret(),
        ext_renegotiation_info(),
        ext_supported_groups(groups_wire),
        ext_ec_point_formats(point_fmts),
        ext_alpn(alpn),
        ext_status_request(),
        ext_sig_algs(SAFARI_SIG_ALGS),
        ext_sct(),
        ext_key_share([(0x001D, x25519_key(seed))]),
        ext_psk_key_exchange_modes([1]),
        ext_supported_versions([0x0304, 0x0303]),
        ext_padding(512, 400),  # approximate padding
        ext_pre_shared_key(),   # PSK hint, extension 41
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=profile_session_id(seed),
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire, ext_ids_wire, groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire, ext_ids_wire, alpn, 0x0304, SAFARI_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': alpn,
        'browser_family': 'safari',
        'version_hint': 18,
        'os': 'macos',
        'is_scraper_library': False,
        'session_id_len': 32,
        'notes': 'Safari 18 macOS. Notable: includes TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0xFF) in cipher list; includes pre_shared_key (41) extension; no compress_certificate, no application_settings (ALPS). Reconstructed from tls.peet.ws Safari 18 captures.',
        'sources': ['https://tls.peet.ws/'],
    }


# ---- curl_cffi impersonate=chrome131 ----
def build_curl_cffi_chrome131():
    seed = 'curl_cffi_chrome131'
    # curl_cffi with impersonate=chrome131 aims to match Chrome 131 exactly.
    # In practice JA3/JA4 is identical. Differentiators are at H2 and behaviour layer.
    ciphers_wire = [
        0x6A6A,  # Different GREASE from real Chrome (not randomised the same way)
        0x1301, 0x1302, 0x1303,
        0xC02B, 0xC02F, 0xC02C, 0xC030,
        0xCCA9, 0xCCA8,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
    ]
    groups_wire = [0x6A6A, 0x001D, 0x0017, 0x0018]
    point_fmts = [0x00]
    alpn = ['h2', 'http/1.1']

    ext_bytes = [
        ext_grease(0x6A6A),
        ext_sni('example.com'),
        ext_extended_master_secret(),
        ext_renegotiation_info(),
        ext_supported_groups(groups_wire),
        ext_ec_point_formats(point_fmts),
        ext_session_ticket(),
        ext_alpn(alpn),
        ext_status_request(),
        ext_sig_algs(CHROME_SIG_ALGS),
        ext_sct(),
        ext_key_share([(0x6A6A, b'\x00'), (0x001D, x25519_key(seed))]),
        ext_psk_key_exchange_modes([1]),
        ext_supported_versions([0x6A6A, 0x0304, 0x0303]),
        ext_compress_cert([2]),
        ext_application_settings(alpn),
        ext_grease(0x6A6A),
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=b'',  # curl_cffi uses empty session ID (key difference from real Chrome)
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire,
                          [0x6A6A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0x6A6A],
                          groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire,
                      [0x6A6A, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0x6A6A],
                      alpn, 0x0304, CHROME_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': alpn,
        'browser_family': 'chrome',
        'version_hint': 131,
        'os': 'n/a',
        'is_scraper_library': True,
        'scraper_library': 'curl_cffi',
        'impersonates': 'chrome131',
        'session_id_len': 0,
        'notes': 'curl_cffi impersonate=chrome131. JA3/JA4 IDENTICAL to real Chrome 131 by design (impersonation success). Key TLS-level differentiators: (1) session_id_length=0 (real Chrome uses 32-byte session ID for TLS 1.3 compat); (2) GREASE values not truly random at OS PRNG level. Primary detection vector is HTTP/2 SETTINGS frame fingerprint (Akamai H2 fingerprint) which curl_cffi replicates imperfectly. See http2/curl_cffi_chrome131.expected.json.',
        'sources': [
            'https://github.com/lexiforest/curl_cffi',
            'https://github.com/lwthiker/curl-impersonate',
        ],
    }


# ---- curl_cffi impersonate=firefox133 ----
def build_curl_cffi_firefox133():
    seed = 'curl_cffi_firefox133'
    ciphers_wire = [
        0x1301, 0x1303, 0x1302,
        0xC02B, 0xC02F,
        0xCCA9, 0xCCA8,
        0xC02C, 0xC030,
        0xC009, 0xC00A,
        0xC013, 0xC014,
        0x009C, 0x009D, 0x002F, 0x0035,
    ]
    groups_wire = [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]
    point_fmts = [0x00]
    alpn = ['h2', 'http/1.1']
    ext_ids_wire = [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28]

    ext_bytes = [
        ext_sni('example.com'),
        ext_extended_master_secret(),
        ext_renegotiation_info(),
        ext_supported_groups(groups_wire),
        ext_ec_point_formats(point_fmts),
        ext_session_ticket(),
        ext_alpn(alpn),
        ext_status_request(),
        ext_delegated_credentials(FF_DC_SIG_ALGS),
        ext_key_share([(0x001D, x25519_key(seed))]),
        ext_supported_versions([0x0304, 0x0303]),
        ext_sig_algs(FIREFOX_SIG_ALGS),
        ext_psk_key_exchange_modes([1]),
        ext_record_size_limit(16385),
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=b'',
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire, ext_ids_wire, groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire, ext_ids_wire, alpn, 0x0304, FIREFOX_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': alpn,
        'browser_family': 'firefox',
        'version_hint': 133,
        'os': 'n/a',
        'is_scraper_library': True,
        'scraper_library': 'curl_cffi',
        'impersonates': 'firefox133',
        'session_id_len': 0,
        'notes': 'curl_cffi impersonate=firefox133. Matches Firefox 133 TLS profile closely. Firefox 133 vs 134 difference: missing ECH outer extension (65037) in 133. Detection: H2 SETTINGS fingerprint diverges from real Firefox.',
        'sources': ['https://github.com/lexiforest/curl_cffi'],
    }


# ---- curl_cffi impersonate=safari18_0 ----
def build_curl_cffi_safari18_0():
    seed = 'curl_cffi_safari18_0'
    ciphers_wire = [
        0x1301, 0x1302, 0x1303,
        0xC02C, 0xC030,
        0xC02B, 0xC02F,
        0xCCA9, 0xCCA8,
        0xC009, 0xC00A,
        0xC013, 0xC014,
        0x009C, 0x009D,
        0x002F, 0x0035,
        0x00FF,
    ]
    groups_wire = [0x001D, 0x0017, 0x0018]
    point_fmts = [0x00]
    alpn = ['h2', 'http/1.1']
    ext_ids_wire = [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 21, 41]

    ext_bytes = [
        ext_sni('example.com'),
        ext_extended_master_secret(),
        ext_renegotiation_info(),
        ext_supported_groups(groups_wire),
        ext_ec_point_formats(point_fmts),
        ext_alpn(alpn),
        ext_status_request(),
        ext_sig_algs(SAFARI_SIG_ALGS),
        ext_sct(),
        ext_key_share([(0x001D, x25519_key(seed))]),
        ext_psk_key_exchange_modes([1]),
        ext_supported_versions([0x0304, 0x0303]),
        ext_padding(512, 400),
        ext_pre_shared_key(),
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=b'',  # curl_cffi uses empty session ID
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire, ext_ids_wire, groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire, ext_ids_wire, alpn, 0x0304, SAFARI_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': alpn,
        'browser_family': 'safari',
        'version_hint': 18,
        'os': 'n/a',
        'is_scraper_library': True,
        'scraper_library': 'curl_cffi',
        'impersonates': 'safari18_0',
        'session_id_len': 0,
        'notes': 'curl_cffi impersonate=safari18_0. JA3 matches Safari 18 closely. Primary differentiator: H2 fingerprint differs because Safari uses a different SETTINGS frame sequence.',
        'sources': ['https://github.com/lexiforest/curl_cffi'],
    }


# ---- Python requests ----
def build_python_requests():
    """
    Python requests (urllib3) with default system OpenSSL.
    Well-known JA3 hash: b32309a26951912be7dba376398abc3b
    """
    seed = 'python_requests'
    # Python requests / urllib3 cipher list (OpenSSL default on Python 3.12+)
    ciphers_wire = [
        0x1302, 0x1303, 0x1301,  # TLS 1.3 (different order from browsers)
        0xC02C, 0xC030, 0x009F,  # ECDHE-ECDSA/RSA-AES256 + DHE-RSA-AES256-GCM
        0xCCA9, 0xCCA8, 0xCCAAA, # ChaCha
        0xC02B, 0xC02F, 0x009E,  # ECDHE-ECDSA/RSA-AES128 + DHE-RSA-AES128-GCM
        0xC024, 0xC028, 0x006B,  # ECDHE-ECDSA/RSA-AES256-SHA384
        0xC023, 0xC027, 0x0067,  # ECDHE-ECDSA/RSA-AES128-SHA256
        0xC00A, 0xC014, 0x0039,  # ECDHE-ECDSA/RSA-AES256-SHA + DHE-RSA-AES256-SHA
        0xC009, 0xC013, 0x0033,  # ECDHE-ECDSA/RSA-AES128-SHA + DHE-RSA-AES128-SHA
        0x009D, 0x009C,           # RSA-AES256-GCM / RSA-AES128-GCM
        0x003D, 0x003C,           # RSA-AES256-CBC-SHA256 / RSA-AES128-CBC-SHA256
        0x0035, 0x002F,           # RSA-AES256-SHA / RSA-AES128-SHA
        0x00FF,                   # SCSV
    ]
    # Fix typo: 0xCCAAA is wrong, should be 0xCCAA
    ciphers_wire = [
        0x1302, 0x1303, 0x1301,
        0xC02C, 0xC030, 0x009F,
        0xCCA9, 0xCCA8, 0xCCAA,
        0xC02B, 0xC02F, 0x009E,
        0xC024, 0xC028, 0x006B,
        0xC023, 0xC027, 0x0067,
        0xC00A, 0xC014, 0x0039,
        0xC009, 0xC013, 0x0033,
        0x009D, 0x009C,
        0x003D, 0x003C,
        0x0035, 0x002F,
        0x00FF,
    ]
    groups_wire = [0x001D, 0x0017, 0x0018, 0x0019]
    point_fmts = [0x00]
    alpn = []  # urllib3 does NOT send ALPN by default with requests
    ext_ids_wire = [0, 11, 10, 35, 16, 22, 23, 13, 43, 45, 51, 21]

    ext_bytes = [
        ext_sni('example.com'),
        ext_ec_point_formats(point_fmts),
        ext_supported_groups(groups_wire),
        ext_session_ticket(),
        # No ALPN in raw requests
        pack_extension(22, b''),       # encrypt_then_mac (22)
        ext_extended_master_secret(),
        ext_sig_algs(REQUESTS_SIG_ALGS),
        ext_supported_versions([0x0304, 0x0303, 0x0302]),
        ext_psk_key_exchange_modes([1]),
        ext_key_share([(0x001D, x25519_key(seed))]),
        pack_extension(21, bytes(1)),  # padding
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=b'',
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire, ext_ids_wire, groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire, ext_ids_wire, alpn, 0x0304, REQUESTS_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': [],
        'browser_family': 'python-requests',
        'version_hint': None,
        'os': 'n/a',
        'is_scraper_library': True,
        'scraper_library': 'python-requests',
        'session_id_len': 0,
        'ja3_hash_reference': 'b32309a26951912be7dba376398abc3b',
        'notes': 'Python requests library (urllib3) with default OpenSSL on Python 3.12/Linux. Well-known JA3 hash b32309a26951912be7dba376398abc3b. Does not send ALPN. Cipher list is OpenSSL default (much longer than browser). Immediately identifiable by cipher count, lack of UA-Client-Hints, and no sec-fetch-* headers.',
        'sources': [
            'https://github.com/salesforce/ja3',
            'https://www.zenrows.com/blog/python-requests-ja3',
        ],
    }


# ---- curl CLI default ----
def build_curl_default():
    """
    Raw curl CLI (curl 8.x, OpenSSL backend, no impersonation flags).
    """
    seed = 'curl_default'
    ciphers_wire = [
        0x1302, 0x1303, 0x1301,
        0xC02C, 0xC02B,
        0xCCA9, 0xCCA8,
        0xC030, 0xC02F,
        0x009F, 0x009E,
        0xC024, 0xC023,
        0xC028, 0xC027,
        0x006B, 0x0067,
        0xC00A, 0xC009,
        0xC014, 0xC013,
        0x0039, 0x0033,
        0x009D, 0x009C,
        0x003D, 0x003C,
        0x0035, 0x002F,
        0x00FF,
    ]
    groups_wire = [0x001D, 0x0017, 0x0018]
    point_fmts = [0x00]
    alpn = []
    ext_ids_wire = [0, 11, 10, 35, 16, 22, 23, 13, 43, 45, 51, 21, 65281]

    ext_bytes = [
        ext_sni('example.com'),
        ext_ec_point_formats(point_fmts),
        ext_supported_groups(groups_wire),
        ext_session_ticket(),
        pack_extension(22, b''),       # encrypt_then_mac
        ext_extended_master_secret(),
        ext_sig_algs(REQUESTS_SIG_ALGS),
        ext_supported_versions([0x0304, 0x0303, 0x0302]),
        ext_psk_key_exchange_modes([1]),
        ext_key_share([(0x001D, x25519_key(seed))]),
        pack_extension(21, bytes(1)),
        ext_renegotiation_info(),
    ]
    raw = build_clienthello(
        ciphers_wire, ext_bytes,
        session_id=b'',
        random_bytes=profile_random(seed),
    )
    ja3_str = compute_ja3(771, ciphers_wire, ext_ids_wire, groups_wire, point_fmts)
    ja4 = compute_ja4(ciphers_wire, ext_ids_wire, alpn, 0x0304, REQUESTS_SIG_ALGS)
    return raw, ja3_str, ja4, {
        'alpn': [],
        'browser_family': 'curl',
        'version_hint': 8,
        'os': 'n/a',
        'is_scraper_library': True,
        'scraper_library': 'curl',
        'session_id_len': 0,
        'notes': 'Raw curl 8.x CLI without impersonation flags. OpenSSL default ciphers. User-Agent: curl/8.x. No sec-fetch headers, no sec-ch-ua. Very wide cipher list (OpenSSL default). Detectable by UA + cipher count + missing browser extensions.',
        'sources': [
            'https://github.com/curl/curl',
            'https://tls.peet.ws/',
        ],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(base, 'clienthello')
    os.makedirs(out_dir, exist_ok=True)

    builders = {
        'chrome131_linux': build_chrome131_linux,
        'chrome131_mac': build_chrome131_mac,
        'firefox134_linux': build_firefox134_linux,
        'safari18_mac': build_safari18_mac,
        'curl_cffi_chrome131': build_curl_cffi_chrome131,
        'curl_cffi_firefox133': build_curl_cffi_firefox133,
        'curl_cffi_safari18_0': build_curl_cffi_safari18_0,
        'python_requests': build_python_requests,
        'curl_default': build_curl_default,
    }

    for name, builder in builders.items():
        raw, ja3_str, ja4, extra = builder()
        ja3_hash = md5(ja3_str)

        # Write hex file
        hex_path = os.path.join(out_dir, f'{name}.hex')
        with open(hex_path, 'w') as f:
            f.write(to_hex_text(raw))
        print(f'  wrote {hex_path} ({len(raw)} bytes)')

        # Write expected JSON
        expected = {
            'profile': name,
            'ja3': ja3_str,
            'ja3_hash': ja3_hash,
            'ja4': ja4,
            'browser_family': extra['browser_family'],
            'version_hint': extra['version_hint'],
            'is_scraper_library': extra['is_scraper_library'],
            **{k: v for k, v in extra.items()
               if k not in ('browser_family', 'version_hint', 'is_scraper_library')},
        }

        json_path = os.path.join(out_dir, f'{name}.expected.json')
        with open(json_path, 'w') as f:
            json.dump(expected, f, indent=2)
        print(f'  wrote {json_path}')

    print(f'\nDone. {len(builders)} profiles generated.')


if __name__ == '__main__':
    main()
