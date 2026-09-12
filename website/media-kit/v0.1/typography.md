# 字体规范 v0.1

原则：系统字体栈，零 webfont 下载（性能与可复现）；代码与哈希一律等宽。

| 用途 | 栈 |
|---|---|
| 正文/UI | `-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", Roboto, Arial, sans-serif` |
| 代码/哈希/徽章 | `ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace` |

## 字号（官网基准）

| 元素 | 字号/行高 |
|---|---|
| 页面标题 | 30px / 1.25（移动端 24px） |
| 正文 | 16px / 1.7 |
| 次要说明 | 14.5px |
| 徽章/水印 | 12–12.5px，等宽 |

## 排版纪律

1. 正文对比度 ≥ 4.5:1（实际 ≥ 7.8:1，见 colors.md）。
2. 中英混排不加人工空格工具链约束，但宣传物料统一"中文与英文/数字之间留半角空格"。
3. 哈希、命令、域标签永不换行折断（等宽 + 横向滚动）。
4. 不使用描边字、发光字；强调用颜色变量，不用字体变形。
