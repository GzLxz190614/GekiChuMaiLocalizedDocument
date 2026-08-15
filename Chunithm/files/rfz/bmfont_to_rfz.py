#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bmfont -> RFZ 字体打包器 (无模板, 全程序化重建)

把 AngelCode BMFont 的产物 (.fnt + 多页 DDS) 直接重建为 SEGA Chunithm 可加载的
RFZ 位图字体, 不依赖任何原始 decompressed.bin 模板。

管线:
    .fnt(+DDS)
      -> metadata.json + glyphs.csv          (字段映射, 见下)
      -> 内嵌纹理 SVO (font_svo_pack)          (段F/G)
      -> decompressed.bin (yabukita 序列化流)  (段A..H, 程序化)
      -> LZW 压缩 + 4 字节 RFZ 头              (rfz_pack.LzwEncoder)

依据: RE/rfz_unpack_spec.md / rfz_pack_spec.md / svo_format.md /
      rfz_glyph_coords_analysis.md。段A..H 重建经 14pt/240pt 模板逐字节复核
      (见 _fullbuild 校验), schema(522B)/对象布局/CRC-32/BZIP2/19字节段H尾均一致。

字段映射 (bmfont -> RFO):
    common.lineHeight/base   -> max_ascent=base, max_descent=lineHeight-base
    common.scaleW/scaleH     -> tex_w/tex_h
    pages 数                 -> tex_page (= DDS 页数)
    info.face                -> name (可 --name 覆盖)
    info.size (绝对值)       -> point   (可 --point 覆盖)
    info.padding[上]         -> glyph_margin (可 --glyph-margin 覆盖)
    char.id                  -> code        (u16; >0xFFFF 跳过并告警)
    char.xadvance            -> cell_inc_x   (cell_inc_y 恒 0)
    char.page                -> page
    char.xoffset             -> origin_x (s16, 笔位水平 bearing, 原样)
    char.yoffset             -> origin_y = base - yoffset (s16, 换算到"基线向上"参考系)
    char.x/y/width/height    -> box_x1/box_y1, box_x2=x+w, box_y2=y+h
    kerning_info_cnt         -> 0 (不导出 kerning 对)

用法:
    python bmfont_to_rfz.py <fnt> --format {text|xml} [选项] [-o out.rfz]
    python bmfont_to_rfz.py bmfont/SEGAHUMMING_32pt_text.fnt --format text \\
        --dds-dir bmfont -o SEGAHUMMING_32pt.rfz
选项:
    --format text|xml   .fnt 解析格式 (由命令行决定, 不看文件名)
    --dds-dir DIR       DDS 页所在目录 (默认与 .fnt 同目录)
    --name S            覆盖 name (默认取 info.face)
    --comment S         覆盖 comment (默认同 name)
    --point N           覆盖 point (默认 abs(info.size))
    --glyph-margin N    覆盖 glyph_margin (默认 info.padding 上)
    --avts-version N    内嵌 SVO 的 AVTS 版本 (默认 3)
    --dump-dir DIR      额外导出 metadata.json/glyphs.csv/decompressed.bin/texture.svo
    -o OUT              输出 .rfz (默认 <fnt 去扩展名>.rfz)
"""
import argparse
import base64
import os
import re
import struct
import sys

import font_svo_pack as fsp
from rfz_pack import LzwEncoder
from rfz_unpack import LzwDecoder, GLYPH_FIELDS

# ---------------------------------------------------------------------------
# 0. 字体无关常量 (经 14pt/240pt 逐字节复核)
# ---------------------------------------------------------------------------
# 外层 YABX schema: namespaces yabukita(1005)/ruhuna(537202737) + 4 类定义
# (ruhuna::Object/Database/Glyph/TextureResource)。与字号/字体无关。
SCHEMA_CONST = base64.b64decode(
    "CXlhYnVraXRhAO0DAAAHcnVodW5hADEQBSAAEXlhYnVraXRhOjpPYmplY3QAAQAAABFydWh1bmE6"
    "OkRhdGFiYXNlAAEBAANpZAABAAAJcGxhdGZvcm0AAQAACGxpYnJhcnkAAQAABW5hbWUAAQAACGNv"
    "bW1lbnQAAQAABmZsYWdzAAEEAAZwb2ludAABAgALbWF4X2FzY2VudAABAgAMbWF4X2Rlc2NlbnQA"
    "AQIADG1heF9nbHlwaF93AAECAAxtYXhfZ2x5cGhfaAABAgAJdGV4X3BhZ2UAAQQABnRleF93AAEC"
    "AAZ0ZXhfaAABAgALdGV4X2xhc3RfaAABAgANZ2x5cGhfbWFyZ2luAAECAApnbHlwaF9jbnQAAQIA"
    "BmdseXBoAAEAAAh0ZXh0dXJlAAEAAAAOcnVodW5hOjpHbHlwaAABAQAFY29kZQABAgALY2VsbF9p"
    "bmNfeAABAgALY2VsbF9pbmNfeQABAgAFcGFnZQABAgAJb3JpZ2luX3gAAQIACW9yaWdpbl95AAEC"
    "AAdib3hfeDEAAQIAB2JveF95MQABAgAHYm94X3gyAAECAAdib3hfeTIAAQIAEWtlcm5pbmdfaW5m"
    "b19jbnQAAQIADWtlcm5pbmdfaW5mbwAAAAAAGHJ1aHVuYTo6VGV4dHVyZVJlc291cmNlAAEBAAVm"
    "aWxlAAEYAAAA")

SEGH = b"\x00" * 19          # 段H: payload 末尾 19 字节全零尾 (计入 payload_size/CRC)


# ---------------------------------------------------------------------------
# 1. bmfont .fnt 解析 (格式由 --format 决定, 不看文件名)
# ---------------------------------------------------------------------------
_INT_RE = re.compile(r"-?\d+")


def _parse_text_fnt(text):
    """解析纯文本 .fnt。返回 (info, common, pages[], chars[])。
    pages[i] = page id=i 行的 file= 名 (按 id 排序)。"""
    info, common, pages, chars = {}, {}, {}, []

    def kv(line):
        out = {}
        for m in re.finditer(r'(\w+)=("([^"]*)"|[^\s]+)', line):
            k = m.group(1)
            v = m.group(3) if m.group(3) is not None else m.group(2)
            out[k] = v
        return out

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("info "):
            info = kv(line)
        elif line.startswith("common "):
            common = kv(line)
        elif line.startswith("page "):
            d = kv(line)
            pages[int(d.get("id", len(pages)))] = d.get("file", "")
        elif line.startswith("char "):
            chars.append(kv(line))
    page_files = [pages[i] for i in sorted(pages)]
    return info, common, page_files, chars


def _parse_xml_fnt(text):
    """解析 XML .fnt (用标准库 ElementTree)。返回 (info, common, pages[], chars[])。"""
    import xml.etree.ElementTree as ET
    root = ET.fromstring(text)
    info = dict(root.find("info").attrib)
    common = dict(root.find("common").attrib)
    pages_el = root.find("pages")
    pages = {}
    if pages_el is not None:
        for p in pages_el.findall("page"):
            pages[int(p.get("id", len(pages)))] = p.get("file", "")
    page_files = [pages[i] for i in sorted(pages)]
    chars = [dict(c.attrib) for c in root.find("chars").findall("char")]
    return info, common, page_files, chars


def parse_fnt(path, fmt):
    text = open(path, encoding="utf-8").read()
    if fmt == "text":
        return _parse_text_fnt(text)
    if fmt == "xml":
        return _parse_xml_fnt(text)
    raise ValueError("未知 --format %r (应为 text 或 xml)" % fmt)


# ---------------------------------------------------------------------------
# 2. bmfont -> metadata + glyphs
# ---------------------------------------------------------------------------
def _int(d, k, default=0):
    v = d.get(k)
    if v is None:
        return default
    m = _INT_RE.search(str(v))
    return int(m.group(0)) if m else default


def fnt_to_meta_glyphs(info, common, chars, opts):
    """把 bmfont 解析结果映射为 RFO metadata 与 glyph 行。"""
    size = abs(_int(info, "size"))
    base = _int(common, "base")
    line_h = _int(common, "lineHeight")
    pad = _int({"p": info.get("padding", "0,0,0,0").split(",")[0]}, "p")

    glyphs = []
    n_neg_off, n_skip_code = 0, 0
    max_w = max_h = 0
    for c in chars:
        code = _int(c, "id")
        if code > 0xFFFF:
            n_skip_code += 1
            continue
        x, y = _int(c, "x"), _int(c, "y")
        w, h = _int(c, "width"), _int(c, "height")
        ox, oy = _int(c, "xoffset"), _int(c, "yoffset")
        # origin_x/origin_y 在游戏 schema 中为 s16 (sub_F270C0/F270F0 注册 "s16")。
        # 参考系换算 (经真实 32pt 字形复核, 见 rfz_glyph_coords_analysis.md §3.4):
        #   - bmfont yoffset = 从"行顶"向下到字形顶 (line-top-down)。
        #   - SEGA origin_y  = 从"基线"向上到字形顶 (baseline-up, 上为正/下为负)。
        #     实证: 逗号/句点 origin_y=-2 (顶略低于基线), 大写/小写 18/13 (顶高于基线)。
        # 故 origin_y = base - yoffset; 直接拷贝 yoffset 会令整行字下沉约 base 像素。
        origin_y = base - oy
        if ox < 0 or origin_y < 0:
            n_neg_off += 1
        max_w, max_h = max(max_w, w), max(max_h, h)
        glyphs.append({
            "code": code,
            "cell_inc_x": _int(c, "xadvance"),
            "cell_inc_y": 0,
            "page": _int(c, "page"),
            "origin_x": ox,
            "origin_y": origin_y,
            "box_x1": x, "box_y1": y,
            "box_x2": x + w, "box_y2": y + h,
            "kerning_info_cnt": 0,
        })
    # RFO 字形按 code 升序 (与 SEGA 原始一致, 便于二分查找)
    glyphs.sort(key=lambda g: g["code"])

    name = opts.get("name") or info.get("face", "BMFont")
    meta = {
        "id": "RHFONTDB", "platform": "DXPC", "library": "ceylon",
        "name": name,
        "comment": opts.get("comment") or name,
        "flags": 0,
        "point": opts.get("point") if opts.get("point") is not None else size,
        "max_ascent": base,
        "max_descent": max(line_h - base, 0),
        "max_glyph_w": max_w,
        "max_glyph_h": max_h,
        "tex_page": _int(common, "pages"),
        "tex_w": _int(common, "scaleW"),
        "tex_h": _int(common, "scaleH"),
        "tex_last_h": _int(common, "scaleH"),     # bmfont 不裁剪末页 -> 全高
        "glyph_margin": opts["glyph_margin"] if opts.get("glyph_margin") is not None else pad,
        "glyph_cnt": len(glyphs),
    }
    warn = {"neg_offsets": n_neg_off, "skipped_codes": n_skip_code}
    return meta, glyphs, warn


# ---------------------------------------------------------------------------
# 3. decompressed.bin 段重建 (经模板逐字节复核)
# ---------------------------------------------------------------------------
def _crc32_bzip2(buf):
    poly = 0x04C11DB7
    tbl = []
    for n in range(256):
        c = n << 24
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFFFFFFFF if (c & 0x80000000) else (c << 1) & 0xFFFFFFFF
        tbl.append(c)
    crc = 0xFFFFFFFF
    for b in buf:
        crc = (tbl[(b ^ (crc >> 24)) & 0xFF] ^ (crc << 8)) & 0xFFFFFFFF
    return (~crc) & 0xFFFFFFFF


def _long_str(s):
    b = s.encode("ascii")
    return struct.pack("<H", len(b) + 1) + b + b"\x00"


def _short_str(s):
    b = s.encode("ascii")
    return bytes([len(b) + 1]) + b + b"\x00"


def _tlv_string(s):
    b = s.encode("utf-8")
    payload = struct.pack("<H", len(b) + 1) + b + b"\x00"
    return struct.pack("<I", len(payload)) + payload


def _build_segB(meta):
    """Database 实例标量/字符串前缀 (id..glyph_cnt)。"""
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


def _build_segC(count):
    """Database._glyph reflist: <u32 size><u32 count><count×u16 localID(=0x2712+i)>。"""
    ids = b"".join(struct.pack("<H", 0x2712 + i) for i in range(count))
    body = struct.pack("<I", count) + ids
    return struct.pack("<I", len(body)) + body


def _build_segD(count):
    """Database._texture reflist: size=6, count=1, TextureResource localID(=0x2712+count)。"""
    body = struct.pack("<I", 1) + struct.pack("<H", 0x2712 + count)
    return struct.pack("<I", len(body)) + body


def _build_segE(glyphs):
    """逐字形对象帧: <u16 tag=3><u32 body=30><code u16 + 10×u16 + kerning(04000000 00000000)>。

    origin_x/origin_y 为 s16 (有符号), 其余 (cell_inc_x/y, box_*) 为 u16。
    """
    out = bytearray()
    kerning = struct.pack("<I", 4) + struct.pack("<I", 0)   # cnt=0
    for g in glyphs:
        body = struct.pack("<H", g["code"])
        for nm in GLYPH_FIELDS:
            fmt = "<h" if nm in ("origin_x", "origin_y") else "<H"
            body += struct.pack(fmt, g[nm])
        body += kerning
        out += struct.pack("<H", 3) + struct.pack("<I", len(body)) + body
    return bytes(out)


def build_decompressed(font_base, meta, glyphs, svo):
    """组装完整 yabukita 解压流 (外层 YABX + schema + 实例 + 内嵌 SVO + 段H 尾)。"""
    top = bytes([7]) + _long_str("ruhuna::Database") + b"\x00" + _short_str(font_base)
    objc = meta["glyph_cnt"] + 2                      # Database + glyph_cnt + TextureResource
    segB = _build_segB(meta)
    segC = _build_segC(meta["glyph_cnt"])
    segD = _build_segD(meta["glyph_cnt"])
    segE = _build_segE(glyphs)
    body_size = len(segB) + len(segC) + len(segD)     # Database 帧 body
    inst = struct.pack("<HHHI", 0, objc, 2, body_size)  # lead_a, obj_count, tag2, body_size
    # TextureResource 帧: tag4 + body(=4+svo) + file blob(u32 len + svo)
    texframe = struct.pack("<HII", 4, 4 + len(svo), len(svo)) + svo
    payload = top + SCHEMA_CONST + inst + segB + segC + segD + segE + texframe + SEGH
    return b"YABX" + struct.pack("<III", 1, len(payload), _crc32_bzip2(payload)) + payload


# ---------------------------------------------------------------------------
# 4. 顶层管线
# ---------------------------------------------------------------------------
def build_rfz(fnt_path, fmt, dds_dir, opts):
    info, common, fnt_pages, chars = parse_fnt(fnt_path, fmt)
    meta, glyphs, warn = fnt_to_meta_glyphs(info, common, chars, opts)

    # DDS 页: 优先用 .fnt 内 page 行的 file= 名; 缺失时回退按 <fnt名>_<id>.dds 推断
    pages, page_files = [], []
    for pid in range(meta["tex_page"]):
        fn = None
        cands = []
        if pid < len(fnt_pages) and fnt_pages[pid]:
            cands.append(fnt_pages[pid])
        stem = os.path.splitext(os.path.basename(fnt_path))[0] \
            .replace("_text", "").replace("_xml", "")
        cands += ["%s_%d.dds" % (stem, pid), "%s_%d.dds" % (info.get("face", ""), pid)]
        for c in cands:
            p = os.path.join(dds_dir, os.path.basename(c))
            if os.path.exists(p):
                fn = p
                break
        if fn is None:
            raise FileNotFoundError("找不到第 %d 页 DDS (试过 %s)" % (pid, ", ".join(cands)))
        page_files.append(os.path.basename(fn))
        pages.append(open(fn, "rb").read())

    # 资源基名 font_base: 用于外层 top header 与内嵌 svo 的 __HmfToSvo__ 名。
    # 默认从 page file= 名剥去 _NNNN.dds 推断 (匹配真实资源名, 如
    # RFO_SEGAKAKUGOTHIC_DB_32pt), 取不到时回退 .fnt 文件名 (去 _text/_xml)。
    font_base = opts.get("font_base")
    if not font_base and fnt_pages and fnt_pages[0]:
        m = re.match(r"(.+?)_\d{4}\.dds$", os.path.basename(fnt_pages[0]))
        if m:
            font_base = m.group(1)
    if not font_base:
        font_base = os.path.splitext(os.path.basename(fnt_path))[0] \
            .replace("_text", "").replace("_xml", "")

    # 内嵌 SVO 的 AVTS 版本: 经 14/18/24/32/60/240pt 全部复核, 恒为 DDS 页数+1
    # (2页→3, 6页→7, 1页→2 ...)。版本字节错误会令游戏解析内层 YABX 错位而崩溃
    # (历史 c0000005@0xEBBEA0)。--avts-version 显式给出时优先, 否则按页数自动推导。
    avts_version = opts.get("avts_version")
    if avts_version is None:
        avts_version = len(pages) + 1
    svo = fsp.build_font_svo(font_base, pages, avts_version)
    stream = build_decompressed(font_base, meta, glyphs, svo)

    # LZW 压缩 + 往返自检 (用已验证解码器)
    enc = LzwEncoder()
    comp = enc.encode(stream)
    dec = LzwDecoder(comp)
    back = bytes(dec.decode())
    if dec.err or back != stream:
        diff = next((k for k in range(min(len(back), len(stream)))
                     if back[k] != stream[k]), -1)
        raise RuntimeError("LZW 往返自检失败 @0x%x (err=%s)" % (diff, dec.err))

    rfz = b"YS" + bytes([2, 0]) + comp
    return rfz, stream, svo, meta, glyphs, warn, page_files, enc.resets, font_base


def main(argv=None):
    ap = argparse.ArgumentParser(description="Pack bmfont (.fnt + DDS) into a Chunithm RFZ font")
    ap.add_argument("fnt", help=".fnt 文件")
    ap.add_argument("--format", required=True, choices=["text", "xml"],
                    help=".fnt 解析格式 (由命令行决定, 不看文件名)")
    ap.add_argument("--dds-dir", help="DDS 页目录 (默认与 .fnt 同目录)")
    ap.add_argument("--name", help="覆盖 name (默认 info.face)")
    ap.add_argument("--comment", help="覆盖 comment (默认同 name)")
    ap.add_argument("--font-base", help="资源基名 (默认由 .fnt 名推断, 去 _text/_xml)")
    ap.add_argument("--point", type=int, help="覆盖 point (默认 abs(info.size))")
    ap.add_argument("--glyph-margin", type=int, help="覆盖 glyph_margin (默认 info.padding 上)")
    ap.add_argument("--avts-version", type=int, default=None,
                    help="内嵌 SVO AVTS 版本 (默认 = DDS 页数+1, 自动推导)")
    ap.add_argument("--dump-dir", help="额外导出 metadata.json/glyphs.csv/decompressed.bin/texture.svo")
    ap.add_argument("-o", "--out", help="输出 .rfz")
    args = ap.parse_args(argv)

    dds_dir = args.dds_dir or os.path.dirname(os.path.abspath(args.fnt))
    opts = {"name": args.name, "comment": args.comment, "font_base": args.font_base,
            "point": args.point, "glyph_margin": args.glyph_margin,
            "avts_version": args.avts_version}
    rfz, stream, svo, meta, glyphs, warn, page_files, resets, font_base = \
        build_rfz(args.fnt, args.format, dds_dir, opts)

    out = args.out or (os.path.splitext(args.fnt)[0]
                       .replace("_text", "").replace("_xml", "") + ".rfz")
    with open(out, "wb") as f:
        f.write(rfz)

    if args.dump_dir:
        import json
        os.makedirs(args.dump_dir, exist_ok=True)
        with open(os.path.join(args.dump_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        with open(os.path.join(args.dump_dir, "glyphs.csv"), "w", encoding="utf-8") as f:
            f.write("code," + ",".join(GLYPH_FIELDS) + "\n")
            for g in glyphs:
                f.write(str(g["code"]) + "," + ",".join(str(g[k]) for k in GLYPH_FIELDS) + "\n")
        open(os.path.join(args.dump_dir, "decompressed.bin"), "wb").write(stream)
        open(os.path.join(args.dump_dir, "texture.svo"), "wb").write(svo)

    print("[OK] -> %s" % out)
    print("  字体: %s  point=%d  字形数=%d  纹理 %d 页 %s  (资源基名 %s)" % (
        meta["name"], meta["point"], meta["glyph_cnt"], meta["tex_page"],
        "x".join(str(meta[k]) for k in ("tex_w", "tex_h")), font_base))
    print("  解压流 %d 字节 -> LZW %d 字节 (RFZ 总 %d, 重置 %d 次)" % (
        len(stream), len(rfz) - 4, len(rfz), resets))
    print("  DDS 页: %s" % ", ".join(page_files))
    if warn["neg_offsets"] or warn["skipped_codes"]:
        print("  [提示] origin 负偏移 %d 个(按 s16 有符号保留); code>0xFFFF 跳过 %d 个"
              % (warn["neg_offsets"], warn["skipped_codes"]))


if __name__ == "__main__":
    main()
