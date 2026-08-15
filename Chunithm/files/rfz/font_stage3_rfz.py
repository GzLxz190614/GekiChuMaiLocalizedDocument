#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""阶段 3/3: decompressed.bin -> RFZ (LZW 压缩 + 4 字节头)

输入:  decompressed.bin (font_stage2_decompressed.py 的产物)
输出:  <out>.rfz  =  "YS" + 0x02 0x00 + LzwEncoder(stream)

压缩后用已验证的 LzwDecoder 做往返自检 (decode(encode)==stream), 不通过即拒绝产出。
LZW 编码器不实现 KwKwK 微优化, 产物与 SEGA 原始非字节一致, 但解码后逐字节一致。
"""
import argparse
import os

from rfz_pack import LzwEncoder
from rfz_unpack import LzwDecoder


def run(bin_path, out_path):
    stream = open(bin_path, "rb").read()
    enc = LzwEncoder()
    comp = enc.encode(stream)

    dec = LzwDecoder(comp)
    back = bytes(dec.decode())
    if dec.err or back != stream:
        diff = next((k for k in range(min(len(back), len(stream)))
                     if back[k] != stream[k]), -1)
        raise RuntimeError("LZW 往返自检失败 @0x%x (err=%s)" % (diff, dec.err))

    rfz = b"YS" + bytes([2, 0]) + comp
    with open(out_path, "wb") as f:
        f.write(rfz)
    print("[OK] 阶段3 -> %s" % out_path)
    print("  解压流 %d 字节 -> LZW %d 字节 (RFZ 总 %d, 重置 %d 次)"
          % (len(stream), len(comp), len(rfz), enc.resets))
    print("  [自检] decode(encode(stream)) == stream (逐字节一致)")
    return rfz


def main(argv=None):
    ap = argparse.ArgumentParser(description="阶段3: decompressed.bin -> rfz")
    ap.add_argument("bin", help="decompressed.bin 路径")
    ap.add_argument("-o", "--out", help="输出 .rfz (默认 <bin 去扩展名>.rfz)")
    args = ap.parse_args(argv)
    out_path = args.out or (os.path.splitext(args.bin)[0] + ".rfz")
    run(args.bin, out_path)


if __name__ == "__main__":
    main()
