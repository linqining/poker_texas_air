#!/usr/bin/env python3
"""ProofPlay 母品牌标志方向生成器 (logo direction generator).

产物:
  out/<dir>/          生产用 SVG (mark / logo / stack / favicon)
  out/boards/         评审板 SVG
  out/_proof-sheet.svg 几何迭代用的草图板

设计约束来自 docs/brand/BRAND_STRATEGY_ZCHAIN_REBRAND.md 第 6 节:
  - 不使用 Z / 链环 / 扑克牌外形 / 花色 / 盾牌
  - 16-24px、单色、打印、favicon 必须成立
  - 字标为定制几何字形, 不依赖任何商业或系统字体
  - 绿色=验证语义; 金色只属于资金与结算, 因此不进入标志

开口量 (dash gap) 一律用真实用户单位计算, 不使用 pathLength:
  librsvg 2.60 对 pathLength 支持不完整, 用了会静默渲染成"没有开口"的假图,
  而假图在肉眼看板时无法与正确产物区分。
"""

import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")

INK = "#101512"
PAPER = "#F3F0E7"
GREEN = "#18A66A"
GREEN_D = "#0E7A4E"
BLUE = "#4967F2"
MUTED = "#93A29A"
LINE = "#314139"
PANEL = "#17201B"

# ---------------------------------------------------------------- geometry ---


def n(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def polar(cx, cy, r, deg):
    a = math.radians(deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


def rr_path(x0, y0, x1, y1, rx, ry=None):
    """顺时针, 起点在顶边左端 (x0+rx, y0)."""
    ry = rx if ry is None else ry
    a = f"A {n(rx)} {n(ry)} 0 0 1"
    return (
        f"M {n(x0 + rx)} {n(y0)} L {n(x1 - rx)} {n(y0)} {a} {n(x1)} {n(y0 + ry)} "
        f"L {n(x1)} {n(y1 - ry)} {a} {n(x1 - rx)} {n(y1)} "
        f"L {n(x0 + rx)} {n(y1)} {a} {n(x0)} {n(y1 - ry)} "
        f"L {n(x0)} {n(y0 + ry)} {a} {n(x0 + rx)} {n(y0)} Z"
    )


def rr_perimeter(x0, y0, x1, y1, rx):
    w, h = x1 - x0, y1 - y0
    return 2 * (w - 2 * rx) + 2 * (h - 2 * rx) + 2 * math.pi * rx


def ring_cut_pos(x0, y0, x1, y1, rx):
    """闭合圆角矩形上 '1:30 方向' 的字形位置 (顶边起点量起)."""
    return (x1 - x0 - 2 * rx) + math.pi * rx / 4.0


def dash_gap(perimeter, center, gap):
    """返回 (dasharray, dashoffset): 在 center 处留出长度 gap 的开口."""
    g = min(gap, perimeter * 0.45)
    start = center - g / 2.0
    dash = perimeter - g
    off = (dash - start) % perimeter
    return f"{n(dash)} {n(g)}", n(off)


def stroke_attrs(sw, color):
    return (
        f'fill="none" stroke="{color}" stroke-width="{n(sw)}" '
        f'stroke-linecap="butt" stroke-linejoin="miter"'
    )


def dash_attrs(da, do):
    return f' stroke-dasharray="{da}" stroke-dashoffset="{do}"'


def cut_path(d, sw, color, perim, center, gap):
    da, do = dash_gap(perim, center, gap)
    return f'<path d="{d}" {stroke_attrs(sw, color)}{dash_attrs(da, do)}/>'


def plain_path(d, sw, color):
    return f'<path d="{d}" {stroke_attrs(sw, color)}/>'


# --------------------------------------------------------------- wordmark ----
# 原生坐标系: 大写高 CH=100 (centerline y 0..100), x-height 顶 y=30, 降部 y=128.

CH, XT, DESC = 100.0, 30.0, 128.0

TYPE_A = dict(
    w=13.0, track=10.0, rx_ratio=0.50, bowl_rc=0.50, arm_r=21.5, hook_r=20.0,
    bowl_drop=56.0, desc=128.0, gap=0.0,
)
TYPE_B = dict(
    w=15.0, track=7.5, rx_ratio=0.26, bowl_rc=0.30, arm_r=18.0, hook_r=14.0,
    bowl_drop=57.0, desc=124.0, gap=25.0,
)


def glyph(ch, t):
    """返回 (子路径列表, 视觉宽度). 子路径 = dict(d, perim, cut)."""
    w, hw = t["w"], t["w"] / 2.0
    out = []

    def sub(d, perim=0.0, cut=None):
        out.append({"d": d, "perim": perim, "cut": cut})

    if ch == "P":
        bh = t["bowl_drop"] - hw                    # bowl 净高 (centerline)
        rc = t["bowl_rc"] * bh
        rc = min(rc, bh / 2.0)
        bw = 48.0 + (t["w"] - TYPE_A["w"]) * 0.5    # bowl 伸出宽度
        bx = hw + bw - rc
        right = max(bh - 2 * rc, 0.0)
        a = f"A {n(rc)} {n(rc)} 0 0 1"
        d = (
            f"M {n(hw)} 0 L {n(hw)} {n(CH)}"
        )
        sub(d)
        bd = (
            f"M {n(hw)} {n(hw)} L {n(bx)} {n(hw)} {a} {n(bx + rc)} {n(hw + rc)} "
            f"L {n(bx + rc)} {n(hw + rc + right)} {a} {n(bx)} {n(hw + bh)} L {n(hw)} {n(hw + bh)}"
        )
        perim = (bx - hw) * 2 + math.pi * rc + right
        center = (bx - hw) + math.pi * rc / 2.0 + right / 2.0
        sub(bd, perim, center)
        return out, bx + rc + hw

    if ch == "r":
        ar = t["arm_r"]
        sub(f"M {n(hw)} {n(XT)} L {n(hw)} {n(CH)}")
        d = f"M {n(hw)} {n(XT + ar)} A {n(ar)} {n(ar)} 0 0 0 {n(hw + ar)} {n(XT)}"
        perim = ar + math.pi * ar / 2.0
        sub(d, perim, ar + math.pi * ar / 4.0)
        return out, hw + ar + hw

    if ch in ("o", "a"):
        d_cl = CH - XT - w                       # x-height 净高 centerline
        x0, y0 = hw, XT + hw
        x1, y1 = x0 + d_cl, y0 + d_cl
        rx = t["rx_ratio"] * d_cl
        d = rr_path(x0, y0, x1, y1, rx)
        perim = rr_perimeter(x0, y0, x1, y1, rx)
        center = ring_cut_pos(x0, y0, x1, y1, rx)
        sub(d, perim, center)
        if ch == "a":
            sub(f"M {n(x1)} {n(XT)} L {n(x1)} {n(CH)}")
        return out, d_cl + w

    if ch == "f":
        sx, hr = hw + 14.0, t["hook_r"]
        a = f"A {n(hr)} {n(hr)} 0 0 1"
        sub(
            f"M {n(sx)} {n(CH)} L {n(sx)} {n(XT - hw)} {a} {n(sx + hr)} {n(XT - hw - hr)}",
            (CH - (XT - hw)) + math.pi * hr / 2.0,
            None,
        )
        cb0, cb1 = sx - hr * 0.7, sx + hr + 2.0
        sub(f"M {n(cb0)} {n(XT)} L {n(cb1)} {n(XT)}")
        return out, max(cb1, sx + hr)

    if ch == "l":
        sub(f"M {n(hw)} 0 L {n(hw)} {n(CH)}")
        return out, w

    if ch == "y":
        top, jx, jy = XT, 42.0, 90.0
        sub(f"M {n(hw)} {n(top + 3.6)} L {n(jx)} {n(jy)}")
        rx0 = 70.0 - hw
        sub(f"M {n(rx0)} {n(top + 3.6)} L {n(rx0 - 37.5)} {n(t['desc'])}")
        return out, 70.0

    raise ValueError(ch)


KERN = {("o", "P"): -6.0, ("l", "a"): -3.0, ("P", "l"): -2.0, ("a", "y"): -2.0}


def wordmark(text, t, color, scale=1.0, x=0.0, y=0.0, cut=False):
    """生成字标 <g>. 返回 (svg, 视觉宽度[已缩放])."""
    tt = dict(t)
    if not cut:
        tt["gap"] = 0.0
    pen = 0.0
    parts = []
    for i, ch in enumerate(text):
        subs, gw = glyph(ch, tt)
        gp = []
        for s in subs:
            if s["cut"] is not None and tt["gap"] > 0:
                gp.append(cut_path(s["d"], tt["w"], color, s["perim"], s["cut"], tt["gap"]))
            else:
                gp.append(plain_path(s["d"], tt["w"], color))
        parts.append(f'<g transform="translate({n(pen)} 0)">{"".join(gp)}</g>')
        pen += gw
        if i < len(text) - 1:
            pen += tt["track"] + KERN.get((ch, text[i + 1]), 0.0)
    svg = f'<g transform="translate({n(x)} {n(y)}) scale({n(scale)})">{"".join(parts)}</g>'
    return svg, pen * scale


# ------------------------------------------------------------------- marks ---

def mark_a(sw=12.0):
    """证印 Open Seal: 右上开口的方印 + 指向开口的验证笔."""
    hw = sw / 2.0
    x0, y0, x1, y1 = 16.0 + hw, 16.0 + hw, 80.0 - hw, 80.0 - hw
    rx = 18.0
    d = rr_path(x0, y0, x1, y1, rx)
    perim = rr_perimeter(x0, y0, x1, y1, rx)
    center = ring_cut_pos(x0, y0, x1, y1, rx)
    ring = cut_path(d, sw, "RING", perim, center, 20.0)
    tick = plain_path(f"M 33.5 48.5 L 44 59.5 L 65 36.5", sw, "TICK")
    return ring, tick, dict(perim=perim, gap=20.0, center=center)


def mark_c(sw=10.0):
    """双面 Private/Public: 一枚方印, 左半实心=牌面私密, 右半账格=结果可验."""
    hw = sw / 2.0
    x0, y0, x1, y1 = 16.0 + hw, 16.0 + hw, 80.0 - hw, 80.0 - hw
    rx = 14.0
    frame = plain_path(rr_path(x0, y0, x1, y1, rx), sw, "FRAME")
    irx = max(rx - hw, 2.0)
    mid = (x0 + x1) / 2.0
    solid = (
        f'<path d="M {n(mid)} {n(y0)} L {n(x0 + irx)} {n(y0)} '
        f'A {n(irx)} {n(irx)} 0 0 0 {n(x0)} {n(y0 + irx)} L {n(x0)} {n(y1 - irx)} '
        f'A {n(irx)} {n(irx)} 0 0 0 {n(x0 + irx)} {n(y1)} L {n(mid)} {n(y1)} Z" fill="FRAME"/>'
    )
    bars = "".join(
        plain_path(f"M {n(mid + 6)} {n(y)} L {n(x1 - 4)} {n(y)}", 8.0, "TICK")
        for y in (40.0, 56.0)
    )
    return solid + frame + bars


# ------------------------------------------------------------------ palette --

def colors(dark, mono, mark_solid, mark_outline, mark_tick):
    if mono:
        c = "currentColor"
        return dict(bg=None, fg=c, word=c, word2=c, ring=c, tick=c,
                    solid=c, outline=c, sub=c)
    if dark:
        return dict(bg=INK, fg=PAPER, word=PAPER, word2=PAPER, ring=PAPER,
                    tick=GREEN, solid=PAPER, outline=GREEN, sub=MUTED)
    return dict(bg=PAPER, fg=INK, word=INK, word2=INK, ring=INK,
                tick=GREEN_D, solid=INK, outline=GREEN_D, sub="#5B675F")


# ------------------------------------------------------------------ lockups --

def svg_doc(w, h, body, title, bg=None):
    rect = f'<rect width="{n(w)}" height="{n(h)}" fill="{bg}"/>' if bg else ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{n(w)}" height="{n(h)}" '
        f'viewBox="0 0 {n(w)} {n(h)}" role="img" aria-label="{title}">{rect}{body}</svg>'
    )


def logo_horizontal(direction, dark=False, mono=False, tagline=False, sub=False):
    C = colors(dark, mono, None, None, None)
    t = TYPE_A if direction in ("a", "c") else TYPE_B
    sw = 12.0
    mh = 96.0                      # mark box
    mscale = 1.75                  # mark 96 -> 168
    mw = mh * mscale
    gap = 34.0
    wscale = 0.98
    wm, wm_w = wordmark("ProofPlay", t, C["word"], scale=wscale, x=0, y=0)
    total_h = 210.0
    # mark 垂直居中; 字标以 cap 区 (0..100) 对齐同一中线
    mark_y = (total_h - mw) / 2.0
    cap_h = CH * wscale
    wm_y = (total_h - cap_h) / 2.0
    body = ""
    x = 0.0
    if direction in ("a", "c"):
        ring, tick, _ = mark_a(sw)
        msvg = (
            f'<g transform="translate({n(x)} {n(mark_y)}) scale({n(mscale)})">'
            + ring.replace("RING", C["ring"]) + tick.replace("TICK", C["tick"])
            + "</g>"
        ) if direction == "a" else (
            f'<g transform="translate({n(x)} {n(mark_y)}) scale({n(mscale)})">'
            + mark_c().replace("SOLID", C["solid"]).replace("OUTLINE", C["outline"]).replace("TICK", C["tick"])
            + "</g>"
        )
        body += msvg
        x = mw + gap
    wm, wm_w = wordmark("ProofPlay", t, C["word"], scale=wscale, x=x, y=wm_y,
                        cut=(direction == "b"))
    body += wm
    if sub:
        body += (
            f'<text x="{n(x + 4 * wscale)}" y="{n(wm_y + 128 * wscale + 34)}" '
            f'font-family="PingFang SC, Hiragino Sans GB, Microsoft YaHei, sans-serif" '
            f'font-size="27" font-weight="700" letter-spacing="13" fill="{C["sub"]}">明局</text>'
        )
    if tagline:
        body += (
            f'<text x="{n(x + wm_w - 2)}" y="{n(wm_y + 128 * wscale + 34)}" text-anchor="end" '
            f'font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="15" '
            f'letter-spacing="3" fill="{C["sub"]}">EVERY ROUND, PROVEN.</text>'
        )
    pad = 40.0
    if mono:
        return svg_doc(x + wm_w + pad, total_h + 40, body, "ProofPlay", None)
    return svg_doc(x + wm_w + pad, total_h + 40, body, "ProofPlay", C["bg"])


def logo_stacked(direction, dark=False, mono=False):
    C = colors(dark, mono, None, None, None)
    t = TYPE_A if direction in ("a", "c") else TYPE_B
    ring, tick, _ = mark_a()
    mscale = 1.35
    mw = 96 * mscale
    wscale = 0.62
    _, wm_w = wordmark("ProofPlay", t, wscale and 1, scale=wscale)
    if direction == "a":
        mark = (f'<g transform="translate({n((mw - 96 * mscale) / 2 + 0)} 0) scale({n(mscale)})">'
                + ring.replace("RING", C["ring"]) + tick.replace("TICK", C["tick"]) + "</g>")
    elif direction == "c":
        mark = (f'<g transform="scale({n(mscale)})">'
                + mark_c().replace("SOLID", C["solid"]).replace("OUTLINE", C["outline"]).replace("TICK", C["tick"]) + "</g>")
    else:
        mark = ""
    wm, wm_w = wordmark("ProofPlay", t, C["word"], scale=wscale,
                        cut=(direction == "b"))
    top = 0.0 if mark else 10.0
    body = mark + f'<g transform="translate(0 {n(mw + 26 + top)})">{wm}</g>'
    text = (f'<text x="{n(wm_w / 2)}" y="{n(mw + 26 + top + 128 * wscale + 32)}" text-anchor="middle" '
            f'font-family="PingFang SC, Hiragino Sans GB, Microsoft YaHei, sans-serif" '
            f'font-size="24" font-weight="700" letter-spacing="12" fill="{C["sub"]}">明局</text>') if sub_on else ""
    w = max(mw, wm_w)
    h = mw + 26 + top + 128 * wscale + (52 if sub_on else 12)
    if mono:
        return svg_doc(w, h, body + text, "ProofPlay stacked")
    return svg_doc(w, h, body + text, "ProofPlay stacked", C["bg"])


sub_on = False


def favicon(direction, px=96, dark=True, mono=False):
    """方形图块: 直接放大 mark; B 用开口的 o."""
    C = colors(dark, mono, None, None, None)
    ring, tick, _ = mark_a(12.0)
    if direction == "a":
        inner = ring.replace("RING", C["ring"]) + tick.replace("TICK", C["tick"])
    elif direction == "c":
        inner = mark_c().replace("SOLID", C["solid"]).replace("OUTLINE", C["outline"]).replace("TICK", C["tick"])
    else:
        t = TYPE_B
        subs, gw = glyph("o", t)
        s = subs[0]
        da, do = dash_gap(s["perim"], s["cut"], t["gap"])
        inner = (f'<g transform="translate({n((96 - (gw + 0)) / 2 + 6)} {n((96 - 70) / 2)})">'
                 f'<path d="{s["d"]}" {stroke_attrs(t["w"], C["ring"])}{dash_attrs(da, do)}/></g>')
    sc = px / 96.0
    return f'<g transform="translate({n(0)} {n(0)}) scale({n(sc)})">{inner}</g>'


def write(rel, text):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


# -------------------------------------------------------------------- main ---

def mark_c_svg(dark, mono):
    C = colors(dark, mono, None, None, None)
    col = "currentColor" if mono else C["word"]
    tick = col if mono else C["tick"]
    return mark_c().replace("FRAME", col).replace("TICK", tick)


def mark_a_svg(dark, mono, sw=12.0):
    C = colors(dark, mono, None, None, None)
    col = "currentColor" if mono else C["word"]
    tick = col if mono else C["tick"]
    ring, tickp, _ = mark_a(sw)
    return ring.replace("RING", col) + tickp.replace("TICK", tick)


# -------------------------------------------------------------------- main ---

def proof_sheet():
    body = ""
    y = 70.0
    for name, t, cut in (("A  w13 track10", TYPE_A, False), ("B  w15 track7.5 cut", TYPE_B, True)):
        wm, w = wordmark("ProofPlay", t, INK, scale=1.0, x=20, y=y, cut=cut)
        body += wm + f'<text x="20" y="{n(y - 26)}" font-family="monospace" font-size="13" fill="#888">{name} width={n(w)}</text>'
        y += 200
    body += f'<g transform="translate(20 {n(y)})">{mark_a_svg(False, False)}</g>'
    body += f'<g transform="translate(150 {n(y)})">{mark_c_svg(False, False)}</g>'
    body += f'<g transform="translate(20 {n(y)}) scale(0.5) translate(0 -110)">{mark_c_svg(False, False)}</g>'
    for i, px in enumerate((16, 24, 32, 48)):
        s = px / 96.0
        body += (f'<g transform="translate({n(320 + i * 72)} 70) scale({n(s)})">{mark_a_svg(False, False)}</g>'
                 f'<g transform="translate({n(320 + i * 72)} 150) scale({n(s)})">{mark_c_svg(False, False)}</g>')
    return svg_doc(700, y + 150, body, "proof sheet")


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    write("_proof-sheet.svg", proof_sheet())
    print("wrote", os.path.join(OUT, "_proof-sheet.svg"))
