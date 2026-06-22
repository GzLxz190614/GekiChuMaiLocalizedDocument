#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阶段 2/3: 中间资产 -> decompressed.bin (yabukita 序列化流)

输入 (默认读取 <in-dir>, 即 font_stage1_assets.py 的产物):
    metadata.json              字体元数据
    glyphs.csv                 逐字形度量
    <font_base>.svo            内嵌纹理 SVO

输出:
    <in-dir>/decompressed.bin  (或 -o 指定)

程序化组装段 A..H (外层 YABX + schema + 实例 + 内嵌 SVO 帧 + 19B 段H 尾),
回填 payload_size 与 CRC-32/BZIP2。逻辑沿用 bmfont_to_rfz.build_decompressed。
资源基名 font_base 取自 SVO 内嵌名 (__HmfToSvo__<font_base>.svo, 剥前缀去 .svo)。
下一阶段: font_stage3_rfz.py (decompressed.bin -> rfz)。
"""
import argparse
import glob
import json
import os

from bmfont_to_rfz import build_decompressed
from rfz_pack import read_glyphs_csv
from rfz_unpack import svo_self_name


def find_svo(in_dir):
    cands = [p for p in glob.glob(os.path.join(in_dir, "*.svo"))]
    if not cands:
        raise FileNotFoundError("在 %s 找不到 .svo" % in_dir)
    if len(cands) > 1:
        raise ValueError("目录含多个 .svo, 请用 --svo 指定: %s" % ", ".join(cands))
    return cands[0]


def run(in_dir, svo_path, out_path):
    meta = json.load(open(os.path.join(in_dir, "metadata.json"), encoding="utf-8"))
    glyphs = read_glyphs_csv(os.path.join(in_dir, "glyphs.csv"))
    if len(glyphs) != meta["glyph_cnt"]:
        raise ValueError("glyphs.csv 行数(%d) != metadata.glyph_cnt(%d)"
                         % (len(glyphs), meta["glyph_cnt"]))
    svo = open(svo_path, "rb").read()

    # font_base: 优先 SVO 内嵌名 (剥 __HmfToSvo__ 与 .svo); 回退 svo 文件名 stem
    name = svo_self_name(svo)
    if name and name.lower().endswith(".svo"):
        font_base = name[:-4]
    else:
        font_base = os.path.splitext(os.path.basename(svo_path))[0]

    stream = build_decompressed(font_base, meta, glyphs, svo)
    with open(out_path, "wb") as f:
        f.write(stream)

    print("[OK] 阶段2 -> %s" % out_path)
    print("  解压流 %d 字节  (资源基名 %s, 字形数 %d, SVO %d 字节)"
          % (len(stream), font_base, meta["glyph_cnt"], len(svo)))
    return stream, font_base


def main(argv=None):
    ap = argparse.ArgumentParser(description="阶段2: 资产 -> decompressed.bin")
    ap.add_argument("in_dir", help="资产目录 (含 metadata.json/glyphs.csv/*.svo)")
    ap.add_argument("--svo", help="SVO 路径 (默认在 in_dir 内唯一 .svo)")
    ap.add_argument("-o", "--out", help="输出 decompressed.bin (默认 in_dir/decompressed.bin)")
    args = ap.parse_args(argv)

    svo_path = args.svo or find_svo(args.in_dir)
    out_path = args.out or os.path.join(args.in_dir, "decompressed.bin")
    run(args.in_dir, svo_path, out_path)


if __name__ == "__main__":
    main()
