#!/usr/bin/env python3
"""全站逐页出图。

为什么要起 HTTP：站内链接是根绝对路径（/assets/...、/docs/...），
file:// 打开会整站断链，截出来的是无样式页面且不报错。

为什么用 iframe 探针量高度：headless Chrome 的 --screenshot 只截窗口，
没有整页参数；给 41 个页面各来一趟「量高 + 截图」就是 82 次启动。
探针页与站点同源，一个页面里塞 41 个 iframe 一次拿全高度，降到 42 次。

产物：design/site/pages/desktop/<slug>.png、.../mobile/<slug>.png
只写 dist/（已 gitignore）与 design/site/pages/，不碰任何入库源文件。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent            # website/tools
WEB = HERE.parent                                  # website
DIST = WEB / "dist"
DEST = WEB.parent / "design" / "site" / "pages"
PORT = int(os.environ.get("PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"


def find_chrome() -> str:
    env = os.environ.get("ZCHAIN_CFT_CHROME")
    if env:
        return env
    for root in (Path("/tmp/chrome"), Path.home() / "Library/Caches"):
        if not root.exists():
            continue
        for cand in root.glob("**/Google Chrome for Testing"):
            return str(cand)
    sys.exit("Chrome for Testing 未找到；请设置 ZCHAIN_CFT_CHROME")


def routes() -> list[tuple[str, str]]:
    """dist 下每个 index.html → (站点路由, slug)"""
    out = []
    for f in sorted(DIST.rglob("index.html")):
        rel = f.parent.relative_to(DIST).as_posix()
        if rel == ".":
            out.append(("/", "home"))
        else:
            out.append(("/" + rel + "/", rel.replace("/", "-")))
    return out


def measure(chrome: str, rs: list[tuple[str, str]], vw: int) -> dict[str, int]:
    """一个同源探针页塞满 iframe，一次读回所有页面高度。

    坑：iframe 不设 width 时默认只有 300px，正文被压成窄栏后
    scrollHeight 会虚高近 2 倍（首轮全站因此带了几千 px 尾部空白）。
    必须显式给到与截图一致的视口宽度。
    """
    frames = "".join(
        f'<iframe data-slug="{quote(slug)}" src="{quote(url)}"></iframe>'
        for url, slug in rs
    )
    probe = f"""<!DOCTYPE html><meta charset="utf-8"><body style="margin:0">
<style>iframe{{display:block;width:{vw}px;height:1000px;border:0}}</style>
{frames}
<script>
window.addEventListener("load", function () {{
  setTimeout(function () {{
    var out = {{}};
    Array.prototype.forEach.call(document.querySelectorAll("iframe"), function (fr) {{
      try {{
        var d = fr.contentDocument.documentElement;
        out[decodeURIComponent(fr.dataset.slug)] =
          Math.max(d.scrollHeight, d.offsetHeight);
      }} catch (e) {{ out[decodeURIComponent(fr.dataset.slug)] = 0; }}
    }});
    var s = document.createElement("div");
    s.id = "__heights";
    s.textContent = JSON.stringify(out);
    document.body.appendChild(s);
  }}, 2500);
}});
</script></body>"""
    (DIST / "__probe.html").write_text(probe, encoding="utf-8")
    try:
        html = subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--hide-scrollbars",
             f"--window-size={vw + 40},1000",
             "--virtual-time-budget=12000", "--dump-dom", f"{BASE}/__probe.html"],
            capture_output=True, text=True, timeout=180,
        ).stdout
    finally:
        (DIST / "__probe.html").unlink(missing_ok=True)

    m = re.search(r'<div id="__heights">(.*?)</div>', html, re.S)
    if not m:
        print("  ! 探针未返回高度，全部回退 1600px", file=sys.stderr)
        return {slug: 1600 for _, slug in rs}
    raw = json.loads(m.group(1).replace("&quot;", '"').replace("&amp;", "&"))
    # 夹逼：太短的页面按视口出，超长页截断到 12000 避免内存爆
    return {k: min(max(int(v or 0), vw == 390 and 900 or 820), 12000)
            for k, v in raw.items()}


def shoot(chrome: str, url: str, w: int, h: int, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [chrome, "--headless", "--disable-gpu", "--hide-scrollbars",
         f"--window-size={w},{h}", "--virtual-time-budget=3500",
         f"--screenshot={out}", url],
        capture_output=True, text=True, timeout=120,
    )


def trim(path: Path, pad: int = 44) -> int:
    """把尾部纯背景空白裁掉，只留 pad px。探针偶发虚高，出图必须干净。"""
    from PIL import Image

    with Image.open(path) as im:
        h = im.height
        if h < 200:
            return h
        strip = im.convert("L").resize((6, h), Image.BILINEAR)
        px = strip.load()
        rows = [sum(px[x, y] for x in range(6)) / 6.0 for y in range(h)]
        bg = rows[-1]
        content = [i for i, v in enumerate(rows) if abs(v - bg) > 4]
        end = (max(content or [0]) + pad)
        if end >= h - 8:
            return h
        im.crop((0, 0, im.width, min(end, h))).save(path)
        return min(end, h)


def apply_ground(ground: str) -> int:
    """给 dist 里每个 <html> 打 data-ground。

    坑：ledger.css 的夜场是 html[data-ground="night"] 选择器，而站点模板的
    <html lang="zh-CN"> 根本没有这个属性 —— 只改 CSS 不写属性，夜场那轮会
    静默出一堆和纸白逐字节相同的假图（首轮就是这样）。dist 是构建产物，改它安全。
    """
    n = 0
    for f in DIST.rglob("*.html"):
        t = f.read_text(encoding="utf-8")
        new = re.sub(
            r'<html([^>]*)>',
            lambda m: "<html" + re.sub(r'\s*data-ground="[^"]*"', '', m.group(1))
                      + f' data-ground="{ground}">' if ground != "paper"
                      else "<html" + re.sub(r'\s*data-ground="[^"]*"', '', m.group(1)) + ">",
            t, count=1)
        if new != t:
            f.write_text(new, encoding="utf-8")
        n += 1
    return n


def main() -> int:
    if not (DIST / "index.html").exists():
        sys.exit("dist/ 未构建；先跑 python3 website/build.py")
    css = DEST.parent / "ledger.css"
    if css.exists():
        (DIST / "assets" / "css" / "main.css").write_text(
            css.read_text(encoding="utf-8"), encoding="utf-8")
        print("已在 dist 内套用 design/site/ledger.css（未触碰入库的 main.css）")
    else:
        print("!! 找不到 ledger.css，将按站点现有样式出图", file=sys.stderr)

    rs = routes()
    ground = os.environ.get("GROUND", "paper")
    print(f"  data-ground={ground} 已写入 {apply_ground(ground)} 个页面")
    # 夜场只出顶层页：docs 29 篇正文结构同构，两套底各出一遍只会让评审台变两倍长
    if os.environ.get("TOPLEVEL"):
        rs = [r for r in rs if r[0].strip("/").count("/") == 0]
    desk = DEST / ("desktop" if ground == "paper" else f"desktop-{ground}")
    mob = DEST / ("mobile" if ground == "paper" else f"mobile-{ground}")
    print(f"{ground} · {len(rs)} 个页面；起 HTTP :{PORT}")
    handler = partial(SimpleHTTPRequestHandler, directory=str(DIST))
    handler.log_message = lambda *a, **k: None
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    chrome = find_chrome()

    try:
        heights = measure(chrome, rs, 1280)
        mobile = [r for r in rs if not r[0].startswith("/docs/")]
        mheights = measure(chrome, mobile, 390) if ground == "paper" else {}
        shutil.rmtree(desk, ignore_errors=True)
        if ground == "paper":
            shutil.rmtree(mob, ignore_errors=True)

        for url, slug in rs:
            h = heights.get(slug, 1600)
            out = desk / f"{slug}.png"
            shoot(chrome, BASE + quote(url), 1280, h, out)
            print(f"  desk {slug:<38} {h}px → {trim(out)}px")

        for url, slug in (mobile if ground == "paper" else []):
            h = mheights[slug]
            out = mob / f"{slug}.png"
            shoot(chrome, BASE + quote(url), 390, h, out)
            print(f"  mob  {slug:<38} {h}px → {trim(out)}px")
    finally:
        srv.shutdown()

    n = len(list(desk.glob("*.png")))
    m = len(list(mob.glob("*.png"))) if mob.exists() else 0
    print(f"\n完成：{ground} desktop {n} 张、mobile {m} 张 → design/site/pages/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
