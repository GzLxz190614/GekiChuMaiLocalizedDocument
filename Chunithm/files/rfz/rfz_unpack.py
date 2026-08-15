#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RFZ 字体解包器 (SEGA Chunithm / yabukita 框架)

用法:
    python rfz_unpack.py <input.rfz> [output_dir]

输出 (默认在 <input去扩展名>_unpacked/ 目录):
    decompressed.bin   解压后的 ChunkProcessorBinary 序列化流
    metadata.json      字体元数据 (point/tex_w/glyph_cnt 等)
    glyphs.csv         逐字形度量 (code/cell_inc/origin/box/kerning_cnt)
    page0.dds, page1.dds, ...  内嵌纹理图集 (ARGB4444 16bpp)

算法依据: RE/rfz_unpack_spec.md (基于 chusanApp.exe IDA 复核)
  - LZW: MSB-first, 9..12 位, 4096 条目反向链字典,
         GIF 式早切码宽, next_code==4094 满表重置(重置后首码字不加表)。
  - 容器: YABX 头 + 自描述 schema + 实例数据 (TLV 字符串 + 内联标量 + localID 引用)。
"""
import sys, os, json, struct

# ---------------------------------------------------------------------------
# 1. LZW 解码器 (复核自 YbLzwDecoder_Fill @0xEA1730 / YbLzwDecoder_Init @0xEA22C0)
# ---------------------------------------------------------------------------
NULL = -1            # 链尾哨兵; 必须区分于 "前缀码 0"
MAX_ENTRIES = 4096
INIT_TOKENS = 256
INIT_BITS = 9


class LzwDecoder:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.bit_buf = 0
        self.bit_cnt = 0                 # bit_buf 中仍有效的位数
        self.code_bits = INIT_BITS
        self.next_code = INIT_TOKENS
        self.prev_code = 0
        self.first_byte = 0
        self.last = [0] * MAX_ENTRIES    # 每条码字序列的最后一个字节
        self.nxt = [NULL] * MAX_ENTRIES  # 指向前缀码字 (NULL = 根)
        for i in range(256):
            self.last[i] = i
        self.window = bytearray(4096)    # 链反转缓冲
        self.resets = 0
        self.err = None

    def _read(self):
        """MSB-first 读取 code_bits 位。"""
        n = self.code_bits
        while self.bit_cnt < n:
            if self.pos >= len(self.data):
                return None
            self.bit_buf = (self.bit_buf << 8) | self.data[self.pos]
            self.pos += 1
            self.bit_cnt += 8
        self.bit_cnt -= n
        code = (self.bit_buf >> self.bit_cnt) & ((1 << n) - 1)
        self.bit_buf &= (1 << self.bit_cnt) - 1
        return code

    def _chain(self, code, out):
        """输出 code 代表的字节串; 返回串首字节。"""
        n = 4096
        e = code
        while self.nxt[e] != NULL:
            n -= 1
            self.window[n] = self.last[e]
            e = self.nxt[e]
        root = self.last[e]
        out.append(root)
        if n < 4096:
            out += self.window[n:4096]
        return root

    def _add_or_reset(self, fb):
        """加表; 当 next_code==4094 时改为满表重置并返回 True。"""
        if self.next_code != MAX_ENTRIES - 2:          # != 4094
            self.last[self.next_code] = fb
            self.nxt[self.next_code] = self.prev_code
            old = self.next_code
            self.next_code += 1
            if old + 2 == (1 << self.code_bits):       # GIF 式早切
                self.code_bits += 1
            return False
        for i in range(INIT_TOKENS, MAX_ENTRIES):      # 清空 256..4095 的链指针
            self.nxt[i] = NULL
        self.next_code = INIT_TOKENS
        self.code_bits = INIT_BITS
        self.resets += 1
        return True

    def _decode_one(self, out, allow_add):
        code = self._read()
        if code is None:
            return False
        if code > self.next_code:
            self.err = "corrupt: code=%d > next_code=%d @out=%d" % (
                code, self.next_code, len(out))
            return False
        if code < self.next_code:
            fb = self._chain(code, out)
        else:                                          # KwKwK
            fb = self._chain(self.prev_code, out)
            out.append(self.first_byte)
        reset = self._add_or_reset(fb) if allow_add else False
        self.first_byte = fb
        self.prev_code = code
        return "reset" if reset else True

    def decode(self):
        out = bytearray()
        code = self._read()
        if code is None:
            return out
        self.next_code = INIT_TOKENS                   # 首码字: 不加表
        self.first_byte = self._chain(code, out)
        self.prev_code = code
        while True:
            r = self._decode_one(out, allow_add=True)
            if r is False:
                break
            if r == "reset":                           # 重置后首码字: 不加表
                if self._decode_one(out, allow_add=False) is False:
                    break
        return out


# ---------------------------------------------------------------------------
# 2. RFZ 头部 + 解压
# ---------------------------------------------------------------------------
def decompress_rfz(raw):
    if len(raw) < 4 or raw[0:2] != b"YS" or raw[2] != 2:
        raise ValueError("不是有效的 RFZ 文件 (期望 magic 'YS' + version 2)")
    dec = LzwDecoder(raw[4:])              # 头部仅消费 4 字节
    out = dec.decode()
    if dec.err:
        raise ValueError("LZW 解码失败: " + dec.err)
    return bytes(out), dec


# ---------------------------------------------------------------------------
# 3. ChunkProcessorBinary 容器解析
# ---------------------------------------------------------------------------
def _u16(d, p): return struct.unpack_from("<H", d, p)[0]
def _u32(d, p): return struct.unpack_from("<I", d, p)[0]


def _read_tlv_string(d, p):
    """字符串/复杂字段 (schema type 00/01): <u32 size><u16 strlen+1><chars\\0>。
    返回 (解码字符串, 下一字段偏移)。"""
    size = _u32(d, p)
    strlen = _u16(d, p + 4)
    s = d[p + 6:p + 6 + max(strlen - 1, 0)].decode("utf-8", "replace")
    return s, p + 4 + size


def parse_metadata(d):
    """解析 ruhuna::Database 实例。返回 (metadata dict, glyph_field_offset)。

    实例字段顺序/类型来自内嵌 schema (所有 6 个字号文件一致):
      id, platform, library, name, comment        (字符串)
      flags(u32) point/max_ascent/max_descent/max_glyph_w/max_glyph_h (u16)
      tex_page(u32) tex_w/tex_h/tex_last_h/glyph_margin/glyph_cnt (u16)
      glyph(数组) texture(blob)
    实例以 id 字段 'RHFONTDB' 起始, 用其 TLV 作锚点 (id 值即 DB magic, 各文件相同)。
    """
    anchor = d.find(b"\x0b\x00\x00\x00\x09\x00RHFONTDB\x00")
    if anchor < 0:
        raise ValueError("未找到 Database 实例 (RHFONTDB id 字段)")
    p = anchor
    meta = {}
    for nm in ("id", "platform", "library", "name", "comment"):
        meta[nm], p = _read_tlv_string(d, p)
    meta["flags"] = _u32(d, p); p += 4
    for nm in ("point", "max_ascent", "max_descent", "max_glyph_w", "max_glyph_h"):
        meta[nm] = _u16(d, p); p += 2
    meta["tex_page"] = _u32(d, p); p += 4
    for nm in ("tex_w", "tex_h", "tex_last_h", "glyph_margin", "glyph_cnt"):
        meta[nm] = _u16(d, p); p += 2
    return meta, p


# 每个字形对象: <u16 marker=3><u32 body_size><body>
# body: code(u16) + cell_inc_x/cell_inc_y/page/origin_x/origin_y/
#       box_x1/box_y1/box_x2/box_y2/kerning_info_cnt (10 字段) + kerning_info
# 字段宽度均 2 字节; origin_x/origin_y 在游戏 schema 中为 s16 (有符号,
# sub_F270C0/F270F0 注册 "s16"), 其余为 u16。
GLYPH_FIELDS = ("cell_inc_x", "cell_inc_y", "page", "origin_x", "origin_y",
                "box_x1", "box_y1", "box_x2", "box_y2", "kerning_info_cnt")
GLYPH_SIGNED = ("origin_x", "origin_y")


def _s16(d, p): return struct.unpack_from("<h", d, p)[0]


def parse_glyphs(d, glyph_field_off, glyph_cnt):
    """解析全部字形对象定义。"""
    size = _u32(d, glyph_field_off)
    count = _u32(d, glyph_field_off + 4)
    # 字形字段体 = count(u32) + count×u16 localID; 对象定义紧随其后
    localid_end = glyph_field_off + 4 + size
    # 跳过 localID 数组后的 10 字节对象表头, 定位首个字形记录 (marker=3,size=30)
    p = d.find(b"\x03\x00\x1e\x00\x00\x00", localid_end)
    if p < 0:
        raise ValueError("未找到字形对象定义起始")
    glyphs = []
    for _ in range(glyph_cnt):
        marker = _u16(d, p)
        body_size = _u32(d, p + 2)
        body = p + 6
        g = {"code": _u16(d, body)}
        for i, nm in enumerate(GLYPH_FIELDS):
            off = body + 2 + 2 * i
            g[nm] = _s16(d, off) if nm in GLYPH_SIGNED else _u16(d, off)
        glyphs.append(g)
        p = body + body_size
    return glyphs


# ---------------------------------------------------------------------------
# 4. 内嵌纹理 (DDS, ARGB4444 16bpp)
# ---------------------------------------------------------------------------
def extract_textures(d):
    """按 'DDS ' magic 扫描并按头部精确切出每张图集。

    dwPitchOrLinearSize(+0x14) 的含义由 dwFlags(+0x08) 决定:
      DDSD_LINEARSIZE(0x80000) -> 该值即整块字节数 (SEGA 原始 DDS);
      DDSD_PITCH(0x8)          -> 该值是每行字节数, 整块 = pitch×height (bmfont DDS)。
    两者皆无效时按 ARGB4444 (2 字节/像素) 估算。
    """
    DDSD_PITCH, DDSD_LINEARSIZE = 0x8, 0x80000
    textures = []
    start = 0
    while True:
        off = d.find(b"DDS ", start)
        if off < 0:
            break
        if _u32(d, off + 4) != 124:        # dwSize 必须为 124, 否则误命中
            start = off + 4
            continue
        flags = _u32(d, off + 8)
        h = _u32(d, off + 12)              # dwHeight
        w = _u32(d, off + 16)              # dwWidth
        pol = _u32(d, off + 20)            # dwPitchOrLinearSize
        if flags & DDSD_LINEARSIZE and pol:
            lin = pol
        elif flags & DDSD_PITCH and pol:
            lin = pol * h                  # 每行字节 × 行数
        else:
            lin = w * h * 2                # ARGB4444 = 2 字节/像素
        total = 128 + lin
        textures.append((off, w, h, bytes(d[off:off + total])))
        start = off + total
    return textures


def extract_svo(d):
    """切出内嵌字体纹理 SVO (Database._texture 的 TextureResource.file blob)。

    解压流末段为一个 ruhuna::TextureResource 对象帧:
        <u16 tag=4><u32 body=4+svo_len><u32 svo_len><AVTS...svo bytes>
    帧紧贴 AVTS magic 之前 10 字节, svo_len 即真正 svo 长度 (不含其后 19 字节
    段H 全零尾)。返回 (svo_bytes, avts_offset) 或 (None, -1)。
    """
    avts = d.find(b"AVTS")
    if avts < 0 or avts < 10:
        return None, -1
    svo_len = _u32(d, avts - 4)            # TextureResource.file blob 长度
    if avts + svo_len > len(d):
        svo_len = len(d) - avts            # 兜底: 取到流尾
    return bytes(d[avts:avts + svo_len]), avts


def cstr(d, o):
    end = d.find(b"\x00", o)
    return d[o:end].decode("ascii", "replace") if end >= 0 else ""


def svo_self_name(svo):
    """取 SVO 自身的内嵌名: chunk 目录条目 0 (内层 YABX, kind=0) 名为
    `__HmfToSvo__<font_base>.svo`, 剥前缀后即 `<font_base>.svo`。无则返回 None。"""
    if not svo or svo[:4] != b"AVTS":
        return None
    name = cstr(svo, 0x80)
    if not name:
        return None
    if name.startswith("__HmfToSvo__"):
        name = name[len("__HmfToSvo__"):]
    return os.path.basename(name.replace("\\", "/"))


def svo_dds_names(svo):
    """从 SVO 的 AVTS chunk 目录取各 DDS 的内嵌名 (剥离 __HmfToSvo__ 前缀)。

    目录: 0x80 起, stride 0x400, name@+0, kind@+0x200(1=DDS), offset@+0x20C。
    返回按页序的文件名列表 (无 DDS 时为空)。
    """
    if not svo or svo[:4] != b"AVTS":
        return []
    names, k = [], 0
    while True:
        base = 0x80 + k * 0x400
        if base + 0x210 > len(svo):
            break
        name = cstr(svo, base)
        if not name:
            break
        kind = _u32(svo, base + 0x200)
        if kind == 1:                      # DDS chunk
            nm = name
            if nm.startswith("__HmfToSvo__"):
                nm = nm[len("__HmfToSvo__"):]
            names.append(os.path.basename(nm.replace("\\", "/")))
        k += 1
    return names


# ---------------------------------------------------------------------------
# 5. 入口
# ---------------------------------------------------------------------------
def unpack(in_path, out_dir):
    raw = open(in_path, "rb").read()
    decompressed, dec = decompress_rfz(raw)
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "decompressed.bin"), "wb") as f:
        f.write(decompressed)

    meta, glyph_field_off = parse_metadata(decompressed)
    glyphs = parse_glyphs(decompressed, glyph_field_off, meta["glyph_cnt"])
    textures = extract_textures(decompressed)
    svo, svo_off = extract_svo(decompressed)

    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    csv_path = os.path.join(out_dir, "glyphs.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("code," + ",".join(GLYPH_FIELDS) + "\n")
        for g in glyphs:
            f.write(str(g["code"]) + "," +
                    ",".join(str(g[k]) for k in GLYPH_FIELDS) + "\n")

    # 内嵌字体纹理 SVO (TextureResource.file blob); 按内嵌名命名, 无则 texture.svo
    svo_name = (svo_self_name(svo) or "texture.svo") if svo else None
    if svo:
        with open(os.path.join(out_dir, svo_name), "wb") as f:
            f.write(svo)

    # DDS 命名: 优先用 SVO chunk 目录里的内嵌名, 否则回退 page%d.dds
    dds_names = svo_dds_names(svo) if svo else []
    saved_names = []
    for i, (off, w, h, blob) in enumerate(textures):
        nm = dds_names[i] if i < len(dds_names) else "page%d.dds" % i
        with open(os.path.join(out_dir, nm), "wb") as f:
            f.write(blob)
        saved_names.append(nm)

    print("[OK] %s" % os.path.basename(in_path))
    print("  解压: %d -> %d 字节 (LZW 重置 %d 次)" %
          (len(raw), len(decompressed), dec.resets))
    print("  字体: %s  point=%d  tex=%dx%d x%d 页  字形数=%d" %
          (meta["comment"], meta["point"], meta["tex_w"], meta["tex_h"],
           meta["tex_page"], meta["glyph_cnt"]))
    print("  解析字形: %d 条 (code %d..%d)" %
          (len(glyphs), glyphs[0]["code"], glyphs[-1]["code"]))
    if svo:
        print("  内嵌 SVO: %d 字节 (AVTS @0x%x) -> %s" % (len(svo), svo_off, svo_name))
    print("  纹理: %d 张 -> %s" %
          (len(textures), ", ".join(saved_names)))
    print("  输出目录: %s" % out_dir)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    in_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.splitext(in_path)[0] + "_unpacked"
    unpack(in_path, out_dir)


if __name__ == "__main__":
    main()
