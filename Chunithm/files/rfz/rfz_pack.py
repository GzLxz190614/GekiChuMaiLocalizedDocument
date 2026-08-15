#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RFZ 字体打包器 (rfz_unpack.py 的逆操作)

用法:
    python rfz_pack.py <unpacked_dir> [output.rfz] [--emit-bin]

输入 (默认读取 <unpacked_dir> 下, 即 rfz_unpack.py 的产物):
    metadata.json      字体元数据 (重建 Database 实例标量/字符串)
    glyphs.csv         逐字形度量 (重建字形定义区)
    page0.dds, page1.dds, ...  纹理图集 (ARGB4444 16bpp, 直接拼接)
    decompressed.bin   ★必需★ 作为"框架模板": HEAD/schema、纹理段头、尾部
                       这些区段为 ChunkProcessor 自描述语法 + 自定义哈希, 未逐字节逆向,
                       故按原样从模板复制; 数据承载区 (实例标量/localID/字形定义/DDS)
                       则完全由上面三类输入重建。

输出:
    <output.rfz>       重新压缩的 RFZ (LZW), 游戏可加载
    --emit-bin 时额外输出 <output>.decompressed.bin (重建后的未压缩流)

设计取舍 (见 RE/rfz_unpack_spec.md):
  - LZW 编码器不实现 KwKwK 微优化, 故产物与 SEGA 原始 RFZ **非字节一致**,
    但经同一(已验证)解码器解压后与重建流 **逐字节一致** → 游戏可正确加载。
  - YABX 哈希 (偏移 0x0c) 在加载时不校验 (IDA 复核 sub_E91400 仅校验 magic),
    故沿用模板哈希; 仅 payload_size (偏移 0x08) 按新长度回填。
  - 框架区 (HEAD/schema/纹理段头/尾部) 随字号变化 (含字体名/尺寸/文件名),
    必须来自同字号的 decompressed.bin 模板。
"""
import sys, os, json, struct

# 复用已验证的解码器做往返校验
from rfz_unpack import LzwDecoder, parse_metadata, GLYPH_FIELDS, GLYPH_SIGNED

MAX_ENTRIES = 4096
INIT_TOKENS = 256
INIT_BITS = 9


# ---------------------------------------------------------------------------
# 1. LZW 编码器 (镜像 YbLzwDecoder_Fill 的字典状态机)
# ---------------------------------------------------------------------------
class LzwEncoder:
    """与 LzwDecoder 严格对偶: 同样的加表时机、GIF 式早切、4094 满表重置。

    贪心最长匹配只使用已存在的字典项, 故产物码字恒 < next_code; 解码端遇到的
    永远是"普通"码字 (不触发 KwKwK), 仍能精确还原。重置时机由相同规则推导,
    保证 MY_decoder(encode(x)) == x。
    """

    def __init__(self):
        self.code_bits = INIT_BITS
        self.next_code = INIT_TOKENS
        self.prev_code = 0
        self.fwd = {}                 # (prefix_code, byte) -> code, 镜像反向链字典
        self.out = bytearray()
        self.acc = 0
        self.nbits = 0
        self.resets = 0

    def _emit(self, code):
        """MSB-first 写入 code_bits 位 (与解码器的大端读取对偶)。"""
        self.acc = (self.acc << self.code_bits) | code
        self.nbits += self.code_bits
        while self.nbits >= 8:
            self.nbits -= 8
            self.out.append((self.acc >> self.nbits) & 0xFF)
        self.acc &= (1 << self.nbits) - 1      # 收窄, 否则 acc 累积成大整数 → O(n²)

    def _flush(self):
        if self.nbits > 0:
            self.out.append((self.acc << (8 - self.nbits)) & 0xFF)
            self.nbits = 0
        return bytes(self.out)

    def _add_or_reset(self, fb):
        """加表; next_code==4094 时改为满表重置并返回 True (镜像解码器)。"""
        if self.next_code != MAX_ENTRIES - 2:          # != 4094
            self.fwd[(self.prev_code, fb)] = self.next_code
            old = self.next_code
            self.next_code += 1
            if old + 2 == (1 << self.code_bits):        # GIF 式早切
                self.code_bits += 1
            return False
        self.fwd.clear()
        self.next_code = INIT_TOKENS
        self.code_bits = INIT_BITS
        self.resets += 1
        return True

    def encode(self, data):
        n = len(data)
        if n == 0:
            return b""
        i = 0
        first = True
        skip_add = False               # 重置后首码字: 不加表
        while i < n:
            # 贪心最长匹配 (仅用已存在字典项)
            code = data[i]
            j = i + 1
            while j < n:
                key = (code, data[j])
                nxt = self.fwd.get(key)
                if nxt is None:
                    break
                code = nxt
                j += 1
            fb = data[i]               # 匹配串首字节 = root(code)
            self._emit(code)
            if not first and not skip_add:
                reset = self._add_or_reset(fb)
                skip_add = reset
            else:
                skip_add = False
            self.prev_code = code
            first = False
            i = j
        return self._flush()


# ---------------------------------------------------------------------------
# 2. 数据承载区重建 (实例标量/字符串、localID 数组、字形定义)
# ---------------------------------------------------------------------------
def _tlv_string(s):
    """schema type 00/01 字符串编码: <u32 size><u16 strlen+1><bytes\\0>。
    size = 该字段从 strlen 起的字节数 = 2 + (strlen)。"""
    b = s.encode("utf-8")
    strlen = len(b) + 1                       # 含结尾 \0
    payload = struct.pack("<H", strlen) + b + b"\x00"
    return struct.pack("<I", len(payload)) + payload


def build_instance_prefix(meta):
    """重建 Database 实例的 id..glyph_cnt 区段 (对应模板 [0x255,0x2e1))。"""
    out = bytearray()
    for nm in ("id", "platform", "library", "name", "comment"):
        out += _tlv_string(meta[nm])
    out += struct.pack("<I", meta["flags"])
    for nm in ("point", "max_ascent", "max_descent", "max_glyph_w", "max_glyph_h"):
        out += struct.pack("<H", meta[nm])
    out += struct.pack("<I", meta["tex_page"])
    for nm in ("tex_w", "tex_h", "tex_last_h", "glyph_margin", "glyph_cnt"):
        out += struct.pack("<H", meta[nm])
    return bytes(out)


def build_localid_array(count):
    """glyph 字段体: <u32 size><u32 count><count×u16 localID>, localID[i]=0x2712+i。"""
    ids = bytearray()
    for i in range(count):
        ids += struct.pack("<H", 0x2712 + i)
    body = struct.pack("<I", count) + ids
    return struct.pack("<I", len(body)) + body


def build_glyph_header(count):
    """字形对象表头 10 字节: 06 00 00 00 01 00 00 00 <u16 last_localid+1>。"""
    return b"\x06\x00\x00\x00\x01\x00\x00\x00" + struct.pack("<H", 0x2712 + count)


def build_glyph_defs(glyphs):
    """逐字形定义区: 每条 <u16 marker=3><u32 body=30><body>。
    body = code(u16) + 10 字段(GLYPH_FIELDS) + kerning(04000000 00000000)。
    origin_x/origin_y 为 s16 (空格字形用 0xFFFF=-1 哨兵), 其余为 u16。"""
    out = bytearray()
    kerning = struct.pack("<I", 4) + struct.pack("<I", 0)   # cnt=0
    for g in glyphs:
        body = struct.pack("<H", g["code"])
        for nm in GLYPH_FIELDS:
            fmt = "<h" if nm in GLYPH_SIGNED else "<H"
            body += struct.pack(fmt, g[nm])
        body += kerning
        assert len(body) == 30, len(body)
        out += struct.pack("<H", 3) + struct.pack("<I", len(body)) + body
    return bytes(out)


def read_glyphs_csv(path):
    glyphs = []
    with open(path, encoding="utf-8") as f:
        header = f.readline().strip().split(",")
        assert header == ["code"] + list(GLYPH_FIELDS), header
        for line in f:
            line = line.strip()
            if not line:
                continue
            vals = [int(x) for x in line.split(",")]
            g = {"code": vals[0]}
            for k, v in zip(GLYPH_FIELDS, vals[1:]):
                g[k] = v
            glyphs.append(g)
    return glyphs


# ---------------------------------------------------------------------------
# 3. 框架边界探测 (在模板 decompressed.bin 中定位各段, 不硬编码偏移)
# ---------------------------------------------------------------------------
def locate_segments(tmpl):
    """返回各段边界, 与字号无关 (靠锚点而非硬编码偏移)。"""
    inst = tmpl.find(b"\x0b\x00\x00\x00\x09\x00RHFONTDB\x00")
    if inst < 0:
        raise ValueError("模板缺少 RHFONTDB 实例锚点")
    meta, glyph_field = parse_metadata(tmpl)
    count = meta["glyph_cnt"]
    size = struct.unpack_from("<I", tmpl, glyph_field)[0]
    localid_end = glyph_field + 4 + size
    glyph_defs = tmpl.find(b"\x03\x00\x1e\x00\x00\x00", localid_end)
    if glyph_defs < 0:
        raise ValueError("模板缺少字形定义区")
    # 遍历字形定义求结尾
    p = glyph_defs
    for _ in range(count):
        assert struct.unpack_from("<H", tmpl, p)[0] == 3
        body = struct.unpack_from("<I", tmpl, p + 2)[0]
        p += 6 + body
    glyph_defs_end = p
    first_dds = tmpl.find(b"DDS ", glyph_defs_end)
    if first_dds < 0:
        raise ValueError("模板缺少 DDS 纹理")
    return {
        "meta": meta, "count": count,
        "inst": inst, "glyph_field": glyph_field,
        "localid_end": localid_end, "glyph_defs": glyph_defs,
        "glyph_defs_end": glyph_defs_end, "first_dds": first_dds,
    }


def find_dds_pages_end(tmpl, first_dds, n_pages):
    """按 DDS 头精确求纹理区结尾, 得到尾部起点。"""
    p = first_dds
    for _ in range(n_pages):
        assert tmpl[p:p + 4] == b"DDS " and struct.unpack_from("<I", tmpl, p + 4)[0] == 124
        h = struct.unpack_from("<I", tmpl, p + 12)[0]
        w = struct.unpack_from("<I", tmpl, p + 16)[0]
        lin = struct.unpack_from("<I", tmpl, p + 20)[0] or (w * h * 2)
        p += 128 + lin
    return p


# ---------------------------------------------------------------------------
# 4. 组装解压流 + 压缩为 RFZ
# ---------------------------------------------------------------------------
def rebuild_stream(unpacked_dir):
    tmpl_path = os.path.join(unpacked_dir, "decompressed.bin")
    if not os.path.exists(tmpl_path):
        raise FileNotFoundError("需要 decompressed.bin 作为框架模板: " + tmpl_path)
    tmpl = open(tmpl_path, "rb").read()
    seg = locate_segments(tmpl)

    meta = json.load(open(os.path.join(unpacked_dir, "metadata.json"), encoding="utf-8"))
    glyphs = read_glyphs_csv(os.path.join(unpacked_dir, "glyphs.csv"))
    if len(glyphs) != meta["glyph_cnt"]:
        raise ValueError("glyphs.csv 行数(%d) != metadata.glyph_cnt(%d)"
                         % (len(glyphs), meta["glyph_cnt"]))

    # 收集 DDS 页: 先按 page%d.dds, 否则按 *_NNNN.dds (rfz_unpack 的内嵌命名) 排序
    pages = []
    i = 0
    while True:
        p = os.path.join(unpacked_dir, "page%d.dds" % i)
        if not os.path.exists(p):
            break
        pages.append(open(p, "rb").read())
        i += 1
    if not pages:
        import glob
        for p in sorted(glob.glob(os.path.join(unpacked_dir, "*_[0-9][0-9][0-9][0-9].dds"))):
            pages.append(open(p, "rb").read())
    if len(pages) != meta["tex_page"]:
        raise ValueError("DDS 页数量(%d) != metadata.tex_page(%d)"
                         % (len(pages), meta["tex_page"]))

    pages_end = find_dds_pages_end(tmpl, seg["first_dds"], len(pages))

    # 各段拼接: 框架来自模板, 数据来自输入
    head = tmpl[:seg["inst"]]                                  # YABX+前导+schema
    inst = build_instance_prefix(meta)                         # 实例标量/字符串
    localid = build_localid_array(meta["glyph_cnt"])           # localID 数组
    ghdr = build_glyph_header(meta["glyph_cnt"])               # 字形表头
    gdefs = build_glyph_defs(glyphs)                           # 字形定义区
    tex_hdr = tmpl[seg["glyph_defs_end"]:seg["first_dds"]]     # 纹理段头(常量)
    dds = b"".join(pages)                                      # 纹理图集
    tail = tmpl[pages_end:]                                    # 尾部(常量)

    stream = bytearray(head + inst + localid + ghdr + gdefs + tex_hdr + dds + tail)
    # 回填 YABX payload_size = 总长 - 16
    struct.pack_into("<I", stream, 8, len(stream) - 16)
    return bytes(stream), tmpl


def pack(unpacked_dir, out_path, emit_bin=False):
    stream, tmpl = rebuild_stream(unpacked_dir)

    # 校验 A: 若输入未改, 重建流应与模板逐字节一致
    if stream == tmpl:
        print("[校验A] 重建流 == 模板 (逐字节一致)")
    else:
        # 定位首个差异以便诊断
        diff = next((k for k in range(min(len(stream), len(tmpl)))
                     if stream[k] != tmpl[k]), min(len(stream), len(tmpl)))
        print("[校验A] 重建流 != 模板 (首差 @0x%x, 长度 %d vs %d) — "
              "若你修改过输入则属正常" % (diff, len(stream), len(tmpl)))

    # LZW 压缩
    enc = LzwEncoder()
    comp = enc.encode(stream)

    # 校验 B: 用已验证解码器解压, 必须 == 重建流
    dec = LzwDecoder(comp)
    back = bytes(dec.decode())
    if dec.err:
        raise RuntimeError("自检解码失败: " + dec.err)
    if back != stream:
        diff = next((k for k in range(min(len(back), len(stream)))
                     if back[k] != stream[k]), -1)
        raise RuntimeError("[校验B] 往返不一致 @0x%x (解出 %d vs 重建 %d)"
                           % (diff, len(back), len(stream)))
    print("[校验B] decode(encode(stream)) == stream (逐字节一致, 重置 %d 次)"
          % enc.resets)

    rfz = b"YS" + bytes([2, 0]) + comp
    with open(out_path, "wb") as f:
        f.write(rfz)

    if emit_bin:
        bin_path = os.path.splitext(out_path)[0] + ".decompressed.bin"
        with open(bin_path, "wb") as f:
            f.write(stream)
        print("  解压流: %s (%d 字节)" % (bin_path, len(stream)))

    meta = json.load(open(os.path.join(unpacked_dir, "metadata.json"), encoding="utf-8"))
    print("[OK] -> %s" % out_path)
    print("  解压流 %d 字节  ->  LZW %d 字节  (RFZ 总 %d 字节)"
          % (len(stream), len(comp), len(rfz)))
    print("  字号 point=%d  字形数=%d  纹理 %d 页"
          % (meta["point"], meta["glyph_cnt"], meta["tex_page"]))


# ---------------------------------------------------------------------------
# 5. 入口
# ---------------------------------------------------------------------------
def main():
    args = [a for a in sys.argv[1:] if a != "--emit-bin"]
    emit_bin = "--emit-bin" in sys.argv
    if not args:
        print(__doc__)
        sys.exit(1)
    unpacked_dir = args[0]
    out_path = args[1] if len(args) > 1 else \
        os.path.normpath(unpacked_dir).rstrip("\\/") + "_repacked.rfz"
    pack(unpacked_dir, out_path, emit_bin)


if __name__ == "__main__":
    main()
