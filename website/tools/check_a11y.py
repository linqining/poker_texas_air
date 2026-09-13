#!/usr/bin/env python3
"""可访问性规则检查（WEB-ACC-1）。

正则级检查 dist/ 全部 HTML：
  1. 所有 <img> 带 alt 属性；
  2. 表单控件（input/select/textarea）有 label（label[for]、包裹式或 aria-label）；
  3. 标题层级不跳级（h1 -> h3 即违规）；
  4. 每页有 viewport meta 与 <html lang=>；
  5. 每个 HTML 恰好一个 <h1>；
  6. 色彩对比：内置官网调色板组合，计算 WCAG 对比度并断言 >= 4.5。

用法：python3 website/tools/check_a11y.py [dist_dir]
退出码：0 = 全部通过；1 = 有问题。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

WEBSITE = Path(__file__).resolve().parent.parent
DEFAULT_DIST = WEBSITE / "dist"

IMG_RE = re.compile(r"<img\b[^>]*>", re.I)
CTRL_RE = re.compile(r"<(?:input|select|textarea)\b[^>]*>", re.I)
HEAD_RE = re.compile(r"<h([1-6])\b", re.I)
VIEWPORT_RE = re.compile(r'<meta\s+name="viewport"', re.I)
LANG_RE = re.compile(r"<html\s+[^>]*lang\s*=\s*[\"'][^\"']+[\"']", re.I)
LABEL_FOR_RE = re.compile(r"""<label\b[^>]*for\s*=\s*["']([^"']+)["']""", re.I)
ID_RE = re.compile(r"""id\s*=\s*["']([^"']+)["']""", re.I)

# 官网调色板（与 assets/css/main.css :root 及 media-kit/v0.1/colors.md 同源）
PALETTE = {
    "bg": "#070d0a", "bg-soft": "#0b1410", "surface": "#101c15",
    "text": "#f0f7f1", "muted": "#abc3b6", "felt": "#37e39c",
    "play": "#66c4ff", "real": "#ffc75a", "danger": "#ff9483",
    "nav-active-text": "#05130c",
}
CONTRAST_PAIRS = [
    ("text on bg", "text", "bg"),
    ("text on surface", "text", "surface"),
    ("muted on bg", "muted", "bg"),
    ("muted on bg-soft", "muted", "bg-soft"),
    ("muted on surface", "muted", "surface"),
    ("felt on bg", "felt", "bg"),
    ("felt on surface", "felt", "surface"),
    ("play on bg", "play", "bg"),
    ("real on bg", "real", "bg"),
    ("real on surface", "real", "surface"),
    ("danger on bg", "danger", "bg"),
    ("nav-active-text on felt", "nav-active-text", "felt"),
]
MIN_CONTRAST = 4.5


def _chan(c: float) -> float:
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hexs: str) -> float:
    h = hexs.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * _chan(r) + 0.7152 * _chan(g) + 0.0722 * _chan(b)


def contrast(fg: str, bg: str) -> float:
    la, lb = luminance(fg), luminance(bg)
    if la < lb:
        la, lb = lb, la
    return (la + 0.05) / (lb + 0.05)


def check_file(f: Path) -> list[str]:
    issues: list[str] = []
    text = f.read_text(encoding="utf-8", errors="replace")
    rel = f

    # 1. img alt
    for img in IMG_RE.findall(text):
        if not re.search(r"""\balt\s*=\s*["'][^"']*["']""", img, re.I):
            issues.append("%s: <img> without alt: %s" % (rel, img[:80]))

    # 2. form labels
    controls = CTRL_RE.findall(text)
    if controls:
        label_fors = set(LABEL_FOR_RE.findall(text))
        for tag in controls:
            m_id = re.search(r"""id\s*=\s*["']([^"']+)["']""", tag, re.I)
            cid = m_id.group(1) if m_id else None
            ok = (
                "aria-label=" in tag
                or "aria-labelledby=" in tag
                or (cid is not None and cid in label_fors)
                or 'type="hidden"' in tag
                or "disabled" in tag and False  # disabled 也不能免 label；此处显式不豁免
            )
            if not ok:
                issues.append("%s: form control without label: %s" % (rel, tag[:80]))

    # 3. heading hierarchy（页内顺序，不允许跳级）
    levels = [int(m) for m in HEAD_RE.findall(text)]
    for prev, cur in zip(levels, levels[1:]):
        if cur > prev + 1:
            issues.append("%s: heading level jump h%d -> h%d" % (rel, prev, cur))

    # 4. viewport / lang
    if not VIEWPORT_RE.search(text):
        issues.append("%s: missing viewport meta" % rel)
    if not LANG_RE.search(text):
        issues.append("%s: missing html lang" % rel)

    # 5. single h1
    if levels.count(1) != 1:
        issues.append("%s: expected exactly 1 h1, found %d" % (rel, levels.count(1)))

    return issues


def main() -> int:
    dist = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DIST
    if not dist.is_dir():
        print("dist not found: %s" % dist)
        return 2
    issues: list[str] = []
    files = sorted(dist.rglob("*.html"))
    for f in files:
        issues += check_file(f)

    # 6. contrast
    contrast_rows = []
    for name, fgk, bgk in CONTRAST_PAIRS:
        ratio = contrast(PALETTE[fgk], PALETTE[bgk])
        contrast_rows.append((name, ratio))
        if ratio < MIN_CONTRAST:
            issues.append("contrast: %s = %.2f (< %.1f)" % (name, ratio, MIN_CONTRAST))

    print("a11y: checked %d pages" % len(files))
    print("contrast (WCAG, minimum %.1f):" % MIN_CONTRAST)
    for name, ratio in contrast_rows:
        print("  %5.2f  %s" % (ratio, name))
    if issues:
        print("A11Y ISSUES: %d" % len(issues))
        for i in issues:
            print("  " + i)
        return 1
    print("a11y check: all rules passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
