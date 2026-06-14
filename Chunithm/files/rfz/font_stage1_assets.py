#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阶段 1/3: bmfont (.fnt + 多页 DDS) -> 中间资产

输出 (默认写入 <out-dir>):
    metadata.json              字体元数据 (Database 标量/字符串)
    glyphs.csv                 逐字形度量 (code + GLYPH_FIELDS)
    <font_base>.svo            内嵌纹理 SVO (AVTS 目录 + 内层 YABX + 各页 DDS)
    <font_base>_NNNN.dds        各页 DDS 原样副本 (便于核对)

下一阶段: font_stage2_decompressed.py (资产 -> decompressed.bin)。

本阶段不生成 decompressed.bin/rfz, 仅做 bmfont 字段映射 + SVO 打包。
字段映射/类型 (s16 origin 等) 完全沿用 bmfont_to_rfz 已验证逻辑。
"""
import argparse
import json
import os
import re

import font_svo_pack as fsp
from bmfont_to_rfz import parse_fnt, fnt_to_meta_glyphs
from rfz_unpack import GLYPH_FIELDS


def resolve_pages(fnt_path, fnt_pages, info, dds_dir, n_pages):
    """按 .fnt 的 page file= 名解析各页 DDS, 缺失时回退 stem/face 命名。
    返回 (pages_bytes[], page_filenames[])。"""
    pages, page_files = [], []
    stem = os.path.splitext(os.path.basename(fnt_path))[0] \
        .replace("_text", "").replace("_xml", "")
    for pid in range(n_pages):
        cands = []
        if pid < len(fnt_pages) and fnt_pages[pid]:
            cands.append(fnt_pages[pid])
        cands += ["%s_%d.dds" % (stem, pid), "%s_%d.dds" % (info.get("face", ""), pid)]
        fn = None
        for c in cands:
            p = os.path.join(dds_dir, os.path.basename(c))
            if os.path.exists(p):
                fn = p
                break
        if fn is None:
            raise FileNotFoundError("找不到第 %d 页 DDS (试过 %s)" % (pid, ", ".join(cands)))
        page_files.append(os.path.basename(fn))
        pages.append(open(fn, "rb").read())
    return pages, page_files


def derive_font_base(opts_font_base, fnt_pages, fnt_path):
    """资源基名: 优先 --font-base; 否则从 page0 file= 剥 _NNNN.dds; 再回退 .fnt 名。"""
    if opts_font_base:
        return opts_font_base
    if fnt_pages and fnt_pages[0]:
        m = re.match(r"(.+?)_\d{4}\.dds$", os.path.basename(fnt_pages[0]))
        if m:
            return m.group(1)
    return os.path.splitext(os.path.basename(fnt_path))[0] \
        .replace("_text", "").replace("_xml", "")


def run(fnt_path, fmt, dds_dir, out_dir, opts):
    info, common, fnt_pages, chars = parse_fnt(fnt_path, fmt)
    meta, glyphs, warn = fnt_to_meta_glyphs(info, common, chars, opts)
    pages, page_files = resolve_pages(fnt_path, fnt_pages, info, dds_dir, meta["tex_page"])
    font_base = derive_font_base(opts.get("font_base"), fnt_pages, fnt_path)
    # AVTS 版本恒为 DDS 页数+1 (经各 pt 复核); 显式 --avts-version 优先。
    avts_version = opts.get("avts_version")
    if avts_version is None:
        avts_version = len(pages) + 1
    svo = fsp.build_font_svo(font_base, pages, avts_version)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "glyphs.csv"), "w", encoding="utf-8") as f:
        f.write("code," + ",".join(GLYPH_FIELDS) + "\n")
        for g in glyphs:
            f.write(str(g["code"]) + "," + ",".join(str(g[k]) for k in GLYPH_FIELDS) + "\n")
    with open(os.path.join(out_dir, font_base + ".svo"), "wb") as f:
        f.write(svo)
    for i, blob in enumerate(pages):
        with open(os.path.join(out_dir, "%s_%04d.dds" % (font_base, i)), "wb") as f:
            f.write(blob)

    print("[OK] 阶段1 -> %s" % out_dir)
    print("  字体: %s  point=%d  字形数=%d  纹理 %d 页 %dx%d  (资源基名 %s)" % (
        meta["name"], meta["point"], meta["glyph_cnt"], meta["tex_page"],
        meta["tex_w"], meta["tex_h"], font_base))
    print("  SVO: %s.svo (%d 字节)  DDS 页: %s" % (
        font_base, len(svo), ", ".join(page_files)))
    if warn["neg_offsets"] or warn["skipped_codes"]:
        print("  [提示] origin 负偏移 %d 个(按 s16 有符号保留); code>0xFFFF 跳过 %d 个"
              % (warn["neg_offsets"], warn["skipped_codes"]))
    return meta, glyphs, font_base


def main(argv=None):
    ap = argparse.ArgumentParser(description="阶段1: bmfont -> metadata/glyphs/svo/dds")
    ap.add_argument("fnt", help=".fnt 文件")
    ap.add_argument("--format", required=True, choices=["text", "xml"],
                    help=".fnt 解析格式 (由命令行决定, 不看文件名)")
    ap.add_argument("--dds-dir", help="DDS 页目录 (默认与 .fnt 同目录)")
    ap.add_argument("-o", "--out-dir", required=True, help="资产输出目录")
    ap.add_argument("--name", help="覆盖 name (默认 info.face)")
    ap.add_argument("--comment", help="覆盖 comment (默认同 name)")
    ap.add_argument("--font-base", help="资源基名 (默认由 page file= 推断)")
    ap.add_argument("--point", type=int, help="覆盖 point (默认 abs(info.size))")
    ap.add_argument("--glyph-margin", type=int, help="覆盖 glyph_margin (默认 padding 上)")
    ap.add_argument("--avts-version", type=int, default=None,
                    help="内嵌 SVO AVTS 版本 (默认 = DDS 页数+1, 自动推导)")
    args = ap.parse_args(argv)

    dds_dir = args.dds_dir or os.path.dirname(os.path.abspath(args.fnt))
    opts = {"name": args.name, "comment": args.comment, "font_base": args.font_base,
            "point": args.point, "glyph_margin": args.glyph_margin,
            "avts_version": args.avts_version}
    run(args.fnt, args.format, dds_dir, args.out_dir, opts)


if __name__ == "__main__":
    main()
