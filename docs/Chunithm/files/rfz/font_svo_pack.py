#!/usr/bin/env python3
"""字体纹理 SVO 生成器 (HmfToSvo/svo)。

把若干 DDS 纹理页打包成 RFZ 字体内嵌的那种 SVO 容器 (AVTS 目录 + 内层 YABX
stevia::Database + DDS chunks)。这是 RFZ 重打包"纹理段"的可参数化重建器, 用于
支持任意页数 / 任意字体名 (现有 rfz_pack.py 只能整段模板复制纹理段)。

格式来源: RE/rfz_glyph_coords_analysis.md / RE/rfz_unpack_spec.md §4.0 / RE/svo_format.md。
逐字节模型经 chusanApp.exe IDA 复核 + 14pt/240pt 字体 svo 往返验证。

关键点:
  - AVTS 头: "AVTS" + u32(version) + 0x78 个 0 (共 0x80 字节)。
  - chunk 目录: 每条目 stride 0x400, name@+0, kind@+0x200(u32: 内层YABX=0/DDS=1),
    ordinal@+0x204(u32: YABX=0, DDS页=1..), size@+0x208(u32), offset@+0x20C(u32)。
    条目顺序 = [内层YABX, DDS_0, DDS_1, ...]; offset 按 0x80 向上对齐。
  - 内层 YABX: 标准 16 字节头 + payload; hash(+12) = CRC-32/BZIP2(payload)
    (非反射, poly 0x04C11DB7, init 0xFFFFFFFF, 末取反)。
    游戏仅当启动标志 bit2 置位才校验该 CRC (sub_E91CC0 @ chusanApp.exe), 但本器恒填正确值。
    payload 末尾补零使 (16 头 + payload) 向上对齐到 0x20; 补零计入 payload_size 与 CRC。
  - YABX payload = top_header + schema(namespaces+7类定义, 字体无关, 内嵌模板)
    + 实例区。实例: u16(lead_a=0) + u16(obj_count) + 对象帧序列。
  - 对象帧: u16(class_tag=类1based索引) + u32(body_size) + body。
  - 字段编码: reflist=u32(4+2n)+u32(n)+n×u16; 空串=u32(2)+u16(0);
    非空串=u32(L+3)+u16(L+1)+chars+\\0; u32 内联; ref=u16。
  - 对象顺序与 localID(从 10001): Database, VD"P", VE, VD"PN", VE, VE, 然后每页(Texture,Image)。
  - 每页: 1 个 stevia::Texture + 1 个 stevia::Image。Image._format=3(ARGB4444),
    _alphaMode=2, _flag=2; Texture._flag=0。

用法:
  python font_svo_pack.py <font_base> <page0.dds> [page1.dds ...] [-o out.svo]
    font_base 例: RFO_SEGAKAKUGOTHIC_DB_14pt (= RHFONTDB 资源基名, 非 metadata.name)
  python font_svo_pack.py --selftest <14pt_unpacked_dir>   # 与原 texture.svo 逐字节比对
"""
import argparse
import base64
import os
import struct
import sys

# schema 区 (namespaces "yabukita"/"stevia" + 7 个类定义)。字体名/页数无关, 所有字体 svo 一致。
_SCHEMA_TEMPLATE = base64.b64decode(
    "CXlhYnVraXRhAO0DAAAHc3RldmlhAOgDAAAAEXlhYnVraXRhOjpPYmplY3QAAQAAABFzdGV2aWE6"
    "OlJlc291cmNlAAEBAAZfbmFtZQAAAAAGX2ZsYWcAAAQACl9mdWxsTmFtZQAAAAAPX3VzZXJQYXJh"
    "bWV0ZXIAAAAAABFzdGV2aWE6OkRhdGFiYXNlAAECAAdfc3RhdGUAAAAABl9tZXNoAAAAAAdfYmF0"
    "Y2gAAAAADl92ZXJ0ZXhCdWZmZXIAAAAADV9pbmRleEJ1ZmZlcgAAAAATX3ZlcnRleERlY2xhcmF0"
    "aW9uAAAAAAlfdGV4dHVyZQAAAAAHX2ltYWdlAAAAAAZfdHJlZQAAAAAAGnN0ZXZpYTo6VmVydGV4"
    "RGVjbGFyYXRpb24AAQIAD192ZXJ0ZXhFbGVtZW50AAEAAAAWc3RldmlhOjpWZXJ0ZXhFbGVtZW50"
    "AAEBAAtfc2VtYW50aWNzAAEEAA1fZWxlbWVudFR5cGUAAQQAB19pbmRleAABBAAAEHN0ZXZpYTo6"
    "VGV4dHVyZQABAgAHX3dyYXBVAAEEAAdfd3JhcFYAAQQAC19taW5GaWx0ZXIAAQQAC19tYWdGaWx0"
    "ZXIAAQQAC19taXBGaWx0ZXIAAQQADV9hbmlzb051bWJlcgABBAAJX2xvZEJpYXMAAQQABF9pZAAB"
    "BAAMX3V2U2V0SW5kZXgAAQQAC191dlNldE5hbWUAAQAAD19hdHRyaWJ1dGVOYW1lAAEAAA1fdGV4"
    "dHVyZVR5cGUAAQAAB19pbWFnZQABAgAADnN0ZXZpYTo6SW1hZ2UAAQIACF9oZWlnaHQAAQQAB193"
    "aWR0aAABBAAQX21heE1pcG1hcExldmVsAAEEAAhfZm9ybWF0AAEEABZfY29tcHJlc3NDdXN0b21P"
    "cHRpb24AAQAAC19hbHBoYU1vZGUAAQQACl9maWxlTmFtZQABAAAPX2NodW5rRmlsZU5hbWUAAQAA"
    "Bl9maWxlAAECABBfbWlwbWFwRmlsZU5hbWUAAQAACl9kYXRhU2l6ZQABBAAAAA==")

# 固定的 VertexDeclaration("P"/"PN") + VertexElement 对象帧块 (实例 #1..#5)。
# 字体 svo 无几何, 但 HmfToSvo 工具恒发出这组空声明, 各字体一致。
_VDVE_BLOCK = base64.b64decode(
    "BAAmAAAABgAAAAEAAAATJwQAAAACAFAAAAAAAAQAAAACAFAABAAAAAAAAAAFAAwAAAAAAAAAAgAA"
    "AAAAAAAEACoAAAAIAAAAAgAAABUnFicFAAAAAwBQTgAAAAAABQAAAAMAUE4ABAAAAAAAAAAFAAwA"
    "AAAAAAAAAgAAAAAAAAAFAAwAAAADAAAACAAAAAAAAAA=")

_LOCALID_BASE = 10001


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


def _short_str(s):
    b = s.encode("ascii")
    return bytes([len(b) + 1]) + b + b"\x00"


def _long_str(s):
    b = s.encode("ascii")
    return struct.pack("<H", len(b) + 1) + b + b"\x00"


def _str_tlv(s):
    b = s.encode("ascii")
    # 空串特例: inner = u16(0) (2 字节, 无 \0); 非空: u16(L+1)+chars+\0。
    inner = struct.pack("<H", 0) if not b else struct.pack("<H", len(b) + 1) + b + b"\x00"
    return struct.pack("<I", len(inner)) + inner


def _reflist(ids):
    return struct.pack("<I", 4 + 2 * len(ids)) + struct.pack("<I", len(ids)) \
        + b"".join(struct.pack("<H", i) for i in ids)


def _u32(v):
    return struct.pack("<I", v)


def _ref(v):
    return struct.pack("<H", v)


def _frame(tag, body):
    return struct.pack("<H", tag) + struct.pack("<I", len(body)) + body


def _align(x, a):
    return (x + a - 1) // a * a


def _dds_dims(dds):
    # DDS: height@+12, width@+16 (u32 LE)
    h, w = struct.unpack_from("<II", dds, 12)
    return w, h


def build_font_svo(font_base, pages, avts_version=3):
    """pages = [dds_bytes, ...] (按页序)。返回完整 svo bytes。

    avts_version: AVTS 头版本 (实测 14pt=3, 240pt=2; 随源资产工具版本而异)。
    """
    n = len(pages)
    b = _LOCALID_BASE
    vd_ids = [b + 1, b + 3]                       # VertexDeclaration "P","PN"
    tex_ids = [b + 6 + 2 * p for p in range(n)]
    img_ids = [b + 7 + 2 * p for p in range(n)]

    # --- Database (实例 #0) ---
    db = _reflist([]) * 5                          # _state,_mesh,_batch,_vertexBuffer,_indexBuffer
    db += _reflist(vd_ids)                          # _vertexDeclaration
    db += _reflist(tex_ids)                         # _texture
    db += _reflist(img_ids)                         # _image
    db += _reflist([])                              # _tree
    db += _str_tlv(font_base)                       # _name
    db += _u32(0)                                   # _flag
    db += _str_tlv(font_base)                       # _fullName
    db += _reflist([])                              # _userParameter

    inst = struct.pack("<HH", 0, 6 + 2 * n)         # lead_a=0, obj_count(Database+5 VD/VE+2n)
    inst += _frame(3, db)                           # tag3 = stevia::Database
    inst += _VDVE_BLOCK                             # #1..#5 固定

    for p in range(n):
        dds = pages[p]
        w, h = _dds_dims(dds)
        # Texture (tag6)
        tb = _u32(2) + _u32(2) + _u32(1) + _u32(1) + _u32(0) + _u32(1) + _u32(0) + _u32(0) + _u32(0)
        tb += _str_tlv("") + _str_tlv("") + _str_tlv("base")   # uvSetName,attributeName,textureType
        tb += _ref(img_ids[p])                                  # _image -> Image localID
        tb += _str_tlv("%s_%04d_tga" % (font_base, p))          # _name
        tb += _u32(0)                                           # _flag
        tb += _str_tlv("ruhuna__%s_%04d_tga" % (font_base, p))  # _fullName
        tb += _reflist([])                                      # _userParameter
        inst += _frame(6, tb)
        # Image (tag7)
        ib = _u32(h) + _u32(w) + _u32(1) + _u32(3)              # height,width,maxMipmapLevel,format=ARGB4444
        ib += _str_tlv("")                                      # _compressCustomOption
        ib += _u32(2)                                           # _alphaMode
        ib += _str_tlv("%s_%04d.dds" % (font_base, p))          # _fileName
        ib += _str_tlv("__HmfToSvo__%s_%04d.dds" % (font_base, p))  # _chunkFileName
        ib += _ref(0)                                           # _file (无对象引用)
        ib += _reflist([])                                      # _mipmapFileName
        ib += _u32(len(dds))                                    # _dataSize
        ib += _str_tlv("%s_%04d" % (font_base, p))              # _name
        ib += _u32(2)                                           # _flag
        ib += _str_tlv("%s_%04d" % (font_base, p))              # _fullName
        ib += _reflist([])                                      # _userParameter
        inst += _frame(7, ib)

    # --- 内层 YABX ---
    top = bytes([4]) + _long_str("HmfToSvo/svo") + bytes([7]) \
        + _long_str("stevia::Database") + b"\x00" + _short_str("__HmfToSvo__" + font_base)
    payload = top + _SCHEMA_TEMPLATE + inst
    # 内层 YABX 总长 (16 头 + payload) 向上对齐到 0x20; 填充零计入 payload 与 CRC。
    payload += b"\x00" * ((-(16 + len(payload))) % 0x20)
    yabx = b"YABX" + struct.pack("<III", 1, len(payload), _crc32_bzip2(payload)) + payload

    # --- chunks: [内层YABX, DDS_0, ...] ---
    chunks = [("__HmfToSvo__%s.svo" % font_base, yabx)]
    for p in range(n):
        chunks.append(("__HmfToSvo__%s_%04d.dds" % (font_base, p), pages[p]))

    dir_size = 0x80 + len(chunks) * 0x400
    offs, cur = [], dir_size
    for _name, blob in chunks:
        cur = _align(cur, 0x80)
        offs.append(cur)
        cur += len(blob)

    out = bytearray(b"AVTS" + struct.pack("<I", avts_version) + b"\x00" * (0x80 - 8))
    for k, (name, blob) in enumerate(chunks):
        e = bytearray(0x400)
        nb = name.encode("ascii")
        e[0:len(nb)] = nb                          # name + 隐含 \0 (bytearray 余位为 0)
        struct.pack_into("<I", e, 0x200, 0 if k == 0 else 1)  # kind: 0=内层YABX, 1=DDS
        struct.pack_into("<I", e, 0x204, k)        # chunk 序号 (YABX=0, DDS 页=1..)
        struct.pack_into("<I", e, 0x208, len(blob))
        struct.pack_into("<I", e, 0x20C, offs[k])
        out += e
    for k, (name, blob) in enumerate(chunks):
        out += b"\x00" * (offs[k] - len(out))
        out += blob
    return bytes(out)


def _selftest(unpacked_dir):
    ref = open(os.path.join(unpacked_dir, "texture.svo"), "rb").read()
    avts_version = struct.unpack_from("<I", ref, 4)[0]
    # 从参考 svo 取 font_base 与 DDS
    import re
    m = re.search(rb"__HmfToSvo__([A-Za-z0-9_]+)\.svo", ref)
    font_base = m.group(1).decode("ascii")
    pages, p = [], 0
    while True:
        fn = os.path.join(unpacked_dir, "page%d.dds" % p)
        if not os.path.exists(fn):
            break
        pages.append(open(fn, "rb").read())
        p += 1
    got = build_font_svo(font_base, pages, avts_version)
    # texture.svo 提取自 RFZ 解压流, 末尾可能含 RFZ 段 H 的全零尾 (不属 svo 本体)
    tail_ok = len(ref) >= len(got) and ref[len(got):] == b"\x00" * (len(ref) - len(got))
    ok = got == ref[:len(got)] and tail_ok
    print("selftest font_base=%s pages=%d avts_v=%d : %s" % (
        font_base, len(pages), avts_version,
        "BYTE-IDENTICAL [OK]" if ok else "MISMATCH [FAIL] (got %d vs ref %d, tail_ok=%s)" % (
            len(got), len(ref), tail_ok)))
    if not ok:
        for i in range(min(len(got), len(ref))):
            if got[i] != ref[i]:
                print("  first diff @0x%x: got %02x ref %02x" % (i, got[i], ref[i]))
                print("  got :", got[max(0, i - 8):i + 8].hex(" "))
                print("  ref :", ref[max(0, i - 8):i + 8].hex(" "))
                break
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description="Pack DDS pages into a font texture SVO")
    ap.add_argument("font_base", nargs="?", help="资源基名, 如 RFO_SEGAKAKUGOTHIC_DB_14pt")
    ap.add_argument("dds", nargs="*", help="DDS 页文件 (按页序)")
    ap.add_argument("-o", "--out", help="输出 .svo")
    ap.add_argument("--selftest", metavar="DIR", help="对解包目录做逐字节往返自检")
    args = ap.parse_args(argv)

    if args.selftest:
        sys.exit(0 if _selftest(args.selftest) else 1)
    if not args.font_base or not args.dds:
        ap.error("需要 font_base 与至少一个 DDS 页 (或用 --selftest)")
    pages = [open(f, "rb").read() for f in args.dds]
    svo = build_font_svo(args.font_base, pages)
    out = args.out or (args.font_base + ".svo")
    open(out, "wb").write(svo)
    print("wrote %s (%d bytes, %d pages)" % (out, len(svo), len(pages)))


if __name__ == "__main__":
    main()
