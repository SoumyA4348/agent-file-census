"""Minimal ORC reader for the parts pyarrow does not expose: file/stripe footers, stripe
statistics and per-row-group positions. Lets us range-read only the row groups we need
from one column of a big remote ORC file instead of the whole stripe.

Only what the Software Heritage export uses: ZSTD (or no) compression, string columns in
DIRECT_V2 encoding with fixed-length values (hex hashes).
"""
from __future__ import annotations

import threading

import zstandard

ZSTD, NONE = 5, 0
_tls = threading.local()   # zstd decompressors are not thread-safe


def _dctx():
    if not hasattr(_tls, "d"):
        _tls.d = zstandard.ZstdDecompressor()
    return _tls.d


# ---- protobuf wire format (just enough) ----
def _varint(b: bytes, i: int):
    r = s = 0
    while True:
        c = b[i]; i += 1
        r |= (c & 0x7F) << s
        if c < 0x80:
            return r, i
        s += 7


def pb(b: bytes) -> dict[int, list]:
    """Decode one message into {field: [values]}; length-delimited values stay bytes."""
    out: dict[int, list] = {}
    i, n = 0, len(b)
    while i < n:
        key, i = _varint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 2:
            ln, i = _varint(b, i)
            v = b[i:i + ln]; i += ln
        elif wt == 1:
            v = b[i:i + 8]; i += 8
        elif wt == 5:
            v = b[i:i + 4]; i += 4
        else:
            raise ValueError(f"wire type {wt}")
        out.setdefault(f, []).append(v)
    return out


def packed(b: bytes) -> list[int]:
    vals, i = [], 0
    while i < len(b):
        v, i = _varint(b, i)
        vals.append(v)
    return vals


def decompress(buf: bytes, kind: int) -> bytes:
    """ORC compression framing: 3-byte header = (chunk_len << 1) | is_original."""
    if kind == NONE:
        return buf
    out, i = [], 0
    while i + 3 <= len(buf):
        h = buf[i] | buf[i + 1] << 8 | buf[i + 2] << 16
        ln, orig = h >> 1, h & 1
        chunk = buf[i + 3:i + 3 + ln]
        out.append(chunk if orig else _dctx().decompress(chunk, max_output_size=1 << 22))
        i += 3 + ln
    return b"".join(out)


class OrcFile:
    """Footer + stripe metadata of one ORC file opened through a pyarrow RandomAccessFile."""

    def __init__(self, f):
        self.f = f
        size = f.size()
        tail = self._read(max(0, size - 65536), min(size, 65536))
        ps_len = tail[-1]
        ps = pb(tail[-1 - ps_len:-1])
        self.compression = ps.get(2, [NONE])[0]
        self.block = ps.get(3, [262144])[0]
        foot_len, meta_len = ps[1][0], ps.get(5, [0])[0]
        need = 1 + ps_len + foot_len + meta_len
        if need > len(tail):
            tail = self._read(size - need, need)
        end = len(tail) - 1 - ps_len
        footer = pb(decompress(tail[end - foot_len:end], self.compression))
        self.meta_raw = tail[end - foot_len - meta_len:end - foot_len]
        self.stride = footer.get(8, [10000])[0]
        self.stripes = []
        for s in footer[3]:
            d = pb(s)
            self.stripes.append(dict(offset=d[1][0], index_len=d[2][0], data_len=d[3][0],
                                     footer_len=d[4][0], rows=d[5][0]))
        self._sfoot: dict[int, dict] = {}

    def _read(self, off, n):
        self.f.seek(off)
        return self.f.read(n)

    def stripe_stats(self):
        """[[ColumnStatistics dict per column] per stripe] from the metadata section."""
        meta = pb(decompress(self.meta_raw, self.compression))
        return [[pb(c) for c in pb(ss).get(1, [])] for ss in meta.get(1, [])]

    def stripe_footer(self, k):
        """Streams of stripe k as {(column, kind): (absolute offset, length)} + encodings."""
        if k in self._sfoot:
            return self._sfoot[k]
        s = self.stripes[k]
        off = s["offset"] + s["index_len"] + s["data_len"]
        sf = pb(decompress(self._read(off, s["footer_len"]), self.compression))
        streams, pos = {}, s["offset"]
        for st in sf.get(1, []):
            d = pb(st)
            kind, col, ln = d.get(1, [0])[0], d.get(2, [0])[0], d.get(3, [0])[0]
            streams[(col, kind)] = (pos, ln)
            pos += ln
        enc = [pb(e).get(1, [0])[0] for e in sf.get(2, [])]
        out = dict(streams=streams, enc=enc)
        self._sfoot[k] = out
        return out

    def row_index(self, k, col):
        """Positions list per row group for column `col` of stripe k."""
        st = self.stripe_footer(k)["streams"]
        off, ln = st[(col, 6)]
        ri = pb(decompress(self._read(off, ln), self.compression))
        return [packed(pb(e).get(1, [b""])[0]) for e in ri.get(1, [])]

    def fixed_strings(self, k, col, width, rows, gap=1 << 18, threads=8):
        """Values of a fixed-width, no-null DIRECT_V2 string column at the given stripe-relative
        rows, reading only the compressed chunks that hold them. Returns {row: bytes}.
        Each row group needs [its start chunk, next group's start + one full chunk] (a group can end
        inside the chunk where the next starts; a chunk is at most block + 3 bytes). Ranges closer
        than `gap` are merged into one request and requests run in parallel."""
        sf = self.stripe_footer(k)
        if (col, 0) in sf["streams"]:
            raise ValueError("column has a PRESENT stream (nulls); fixed-width read unsafe")
        if sf["enc"][col] not in (0, 2):
            raise ValueError("column not direct-encoded")
        data_off, data_len = sf["streams"][(col, 1)]
        starts = [(p[0], p[1]) for p in self.row_index(k, col)]
        by_group: dict[int, list[int]] = {}
        for r in rows:
            by_group.setdefault(r // self.stride, []).append(r)
        spans = []   # [lo, hi, [groups]] in compressed DATA offsets
        for g in sorted(by_group):
            c0 = starts[g][0]
            hi = min(data_len, (starts[g + 1][0] if g + 1 < len(starts) else data_len) + 3 + self.block)
            if spans and c0 - spans[-1][1] <= gap:
                spans[-1][1] = max(spans[-1][1], hi)
                spans[-1][2].append(g)
            else:
                spans.append([c0, hi, [g]])

        def fetch(sp):
            lo, hi, gs = sp
            return sp, self.f.read_at(hi - lo, data_off + lo)
        if len(spans) > 1 and threads > 1:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(min(threads, len(spans))) as ex:
                got = list(ex.map(fetch, spans))
        else:
            got = [fetch(sp) for sp in spans]
        out = {}
        for (lo, hi, gs), raw in got:
            for g in gs:
                c0, u0 = starts[g]
                c1 = starts[g + 1][0] if g + 1 < len(starts) else data_len
                plain = self._chunks(raw, c0 - lo, c1 - lo)
                base = g * self.stride
                for r in by_group[g]:
                    o = u0 + (r - base) * width
                    out[r] = plain[o:o + width]
        return out

    def var_strings(self, k, col, rows, gap=1 << 18, threads=8):
        """Values of a no-null DIRECT_V2 string/binary column at the given stripe-relative rows, reading only
        the LENGTH and DATA chunks of the row groups that hold them (not the whole column). -> {row: bytes}
        Row-index positions per group: [data chunk, data offset, length chunk, length offset, values to skip].
        A group's lengths can sit in an RLE run that starts at the next group's position and runs past
        that chunk, so LENGTH spans include one extra chunk."""
        sf = self.stripe_footer(k)
        if (col, 0) in sf["streams"]:
            raise ValueError("column has a PRESENT stream (nulls)")
        if sf["enc"][col] not in (0, 2):
            raise ValueError("column not direct-encoded")
        d_off, d_len = sf["streams"][(col, 1)]
        l_off, l_len = sf["streams"][(col, 2)]
        pos = self.row_index(k, col)
        by_group: dict[int, list[int]] = {}
        for r in rows:
            by_group.setdefault(r // self.stride, []).append(r)
        step = 3 + self.block
        groups = sorted(by_group)

        def nxt(g, i, n):
            return pos[g + 1][i] if g + 1 < len(pos) else n
        lspans = [(pos[g][2], min(l_len, nxt(g, 2, l_len) + 2 * step), g) for g in groups]
        dspans = [(pos[g][0], min(d_len, nxt(g, 0, d_len) + step), g) for g in groups]
        lraw = self._fetch_spans(l_off, lspans, gap, threads)
        draw = self._fetch_spans(d_off, dspans, gap, threads)
        out = {}
        for g in groups:
            base, need = g * self.stride, sorted(by_group[g])
            lo, raw = lraw[g]
            plain = self._chunks(raw, pos[g][2] - lo, nxt(g, 2, l_len) - lo, extra=1)
            lens, _ = rle2(plain, pos[g][3], need[-1] - base + 1, skip=pos[g][4])
            lo, raw = draw[g]
            data = self._chunks(raw, pos[g][0] - lo, nxt(g, 0, d_len) - lo)
            o, starts = pos[g][1], []
            for ln in lens:
                starts.append(o)
                o += ln
            for r in need:
                i = r - base
                out[r] = data[starts[i]:starts[i] + lens[i]]
        return out

    def _fetch_spans(self, stream_off, spans, gap, threads):
        """spans [(lo, hi, group)] in stream offsets -> {group: (merged lo, raw bytes)}; close spans merged."""
        merged = []
        for lo, hi, g in sorted(spans):
            if merged and lo - merged[-1][1] <= gap:
                merged[-1][1] = max(merged[-1][1], hi)
                merged[-1][2].append(g)
            else:
                merged.append([lo, hi, [g]])

        def fetch(m):
            return m, self.f.read_at(m[1] - m[0], stream_off + m[0])
        if len(merged) > 1 and threads > 1:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(min(threads, len(merged))) as ex:
                got = list(ex.map(fetch, merged))
        else:
            got = [fetch(m) for m in merged]
        return {g: (m[0], raw) for m, raw in got for g in m[2]}

    def _chunks(self, raw, i, end, extra=0):
        """Decompress whole chunks starting at raw[i] up to and including the one that starts at `end`,
        plus `extra` more complete chunks if raw holds them."""
        if self.compression == NONE:
            return raw[i:]
        out = []
        while i + 3 <= len(raw):
            if i > end:
                if extra <= 0:
                    break
                extra -= 1
            h = raw[i] | raw[i + 1] << 8 | raw[i + 2] << 16
            ln, orig = h >> 1, h & 1
            if i > end and i + 3 + ln > len(raw):
                break   # incomplete extra chunk
            chunk = raw[i + 3:i + 3 + ln]
            out.append(chunk if orig else _dctx().decompress(chunk, max_output_size=1 << 22))
            i += 3 + ln
        return b"".join(out)


# ---- ORC RLE v2 integers (LENGTH streams of direct string columns, int columns) ----
FBS = list(range(1, 25)) + [26, 28, 30, 32, 40, 48, 56, 64]   # 5-bit encoded width -> bits


def _closest_fixed_bits(n):
    if n <= 24:
        return max(n, 1)
    return next(b for b in (26, 28, 30, 32, 40, 48, 56, 64) if n <= b)


def _unpack(buf, pos, n, w):
    """n big-endian bit-packed values of w bits starting at byte pos -> (values, next byte pos)."""
    if n <= 0:
        return [], pos
    if w == 0:
        return [0] * n, pos
    nbytes = (n * w + 7) // 8
    big = int.from_bytes(buf[pos:pos + nbytes], "big") >> (nbytes * 8 - n * w)
    mask = (1 << w) - 1
    return [(big >> (w * (n - 1 - i))) & mask for i in range(n)], pos + nbytes


def _uvarint(b, i):
    r = s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        if c < 0x80:
            return r, i
        s += 7


def _zz(v):
    return (v >> 1) ^ -(v & 1)


def rle2(buf, pos, n, signed=False, skip=0):
    """Decode n values of an RLEv2 stream whose run header is at buf[pos], after skipping `skip` values
    of that first run (row-index semantics). -> (values, byte pos after the last run read)."""
    out, need = [], n + skip
    while len(out) < need:
        h = buf[pos]
        e = h >> 6
        if e == 0:   # SHORT_REPEAT: 3-10 copies of one value
            w = ((h >> 3) & 7) + 1
            v = int.from_bytes(buf[pos + 1:pos + 1 + w], "big")
            out.extend([_zz(v) if signed else v] * ((h & 7) + 3))
            pos += 1 + w
            continue
        ln = ((h & 1) << 8 | buf[pos + 1]) + 1
        if e == 1:   # DIRECT
            vals, pos = _unpack(buf, pos + 2, ln, FBS[(h >> 1) & 0x1F])
            out.extend([_zz(v) for v in vals] if signed else vals)
        elif e == 2:   # PATCHED_BASE
            w = FBS[(h >> 1) & 0x1F]
            b2, b3 = buf[pos + 2], buf[pos + 3]
            bw, pw = ((b2 >> 5) & 7) + 1, FBS[b2 & 0x1F]
            pgw, pll = ((b3 >> 5) & 7) + 1, b3 & 0x1F
            pos += 4
            base = int.from_bytes(buf[pos:pos + bw], "big")
            pos += bw
            msb = 1 << (bw * 8 - 1)
            if base & msb:   # sign-magnitude
                base = -(base & ~msb)
            data, pos = _unpack(buf, pos, ln, w)
            patches, pos = _unpack(buf, pos, pll, _closest_fixed_bits(pw + pgw))
            pmask, idx, pi = (1 << pw) - 1, 0, 0
            while pi < pll:
                gp, patch = patches[pi] >> pw, patches[pi] & pmask
                while gp == 255 and patch == 0 and pi + 1 < pll:   # gap longer than 255
                    idx += 255
                    pi += 1
                    gp, patch = patches[pi] >> pw, patches[pi] & pmask
                idx += gp
                data[idx] |= patch << w
                pi += 1
            out.extend(base + d for d in data)
        else:   # DELTA
            ew = (h >> 1) & 0x1F
            w = FBS[ew] if ew else 0
            base, pos = _uvarint(buf, pos + 2)
            if signed:
                base = _zz(base)
            db, pos = _uvarint(buf, pos)
            db = _zz(db)
            run = [base]
            if ln > 1:
                run.append(base + db)
                if w == 0:   # fixed delta
                    for _ in range(ln - 2):
                        run.append(run[-1] + db)
                else:
                    deltas, pos = _unpack(buf, pos, ln - 2, w)
                    sgn = 1 if db >= 0 else -1
                    for d in deltas:
                        run.append(run[-1] + sgn * d)
            out.extend(run)
    return out[skip:need], pos
