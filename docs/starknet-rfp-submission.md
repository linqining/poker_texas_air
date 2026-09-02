# STRK20 RFP "Private Poker" 投标叙事（Plan D P2.3 交付）

> 对应 RFP：https://strk20.starknet.io/rfp/private-poker（Idea 02 · Gaming）。
> 本文是对外材料的叙事骨架；术语对外展开，不使用内部缩写（DAPV 等
> 首次出现必须解释）。

## 一句话定位

一个无需可信发牌者的链上结算扑克：**发牌公平性由多方联合洗牌 +
可验证证明保证（超过 RFP V1 的 trusted-dealer 要求，直接是 V2 级
mental poker）**，底牌从发牌到摊牌前对包括运营方在内的任何人都不可
解密；资金全程走 STRK20 privacy pool，交易经 paymaster 提交，
玩家身份与资金链路解耦。

## 逐条回应 RFP 验收信号

| RFP 要求 | 我们的回答 |
|---|---|
| No trusted server, no admin who can peek at cards | 发牌公平：N 方联合洗牌（阈值 ElGamal + 逐层置换证明），≥1 诚实玩家则无人（含服务器）知道牌序——比 RFP V1 的"可信发牌者 + STARK 证明"更强。牌面隐私：持有者份额扣到摊牌才交、本地解密；客户端侧另有编排守卫（Plan D P0.1），主动恶意服务器也只剩踢人/停服的活性攻击面，无牌面泄露 |
| PokerGame 合约 privacy_invoke（deal/bet/fold/reveal/settle） | 资金与结算侧已上链：STRK20 `privacy_invoke` 匿名化买入（poker_vault_anonymizer）+ 每手链上结算（座位所有权认可的 ρ 折叠单点校验 + STARK 摘要注册）。牌局动作链下、每手一次链上锚定（hand_binding 承诺链）——bet amounts 本就 public by design，上链的是可验证性而非动作流水 |
| STARK proofs of correct dealing | STWO 管线就绪（结算 G 层 canonical STARK 聚合摘要已注册上链）；洗牌语句的 STARK 化成本模型已实测（见 docs/plan-d-p3-metrics.md），曲线已迁移到 Cairo 原生 STARK 曲线，EC_OP builtin 让全残差链上验证可负担 |
| Cards as encrypted notes, only holder decrypts | 手牌 = 阈值 ElGamal 密文（channel key 语义），资金 = STRK20 note（shield 入池 / open note 找零 / viewing key）；摊牌公开与 note 开封同构 |
| Betting settles through the privacy pool | 买入：privacy pool → privacy_invoke → vault 记账（观察者无法关联出资人）；提现 unshield 方向为下一步合约工作（规范已交付） |
| Paymaster submits all tx | 已实现：paymaster 中继 + 多 RPC failover；钱包（Ready）签名，诚实边界（回退路径直签会暴露 sender）有文档 |
| Viewing keys | 客户端本地生成，池原生支持；审计/合规走"授权查看 + 争议驱动 STARK 复核"，不牺牲默认隐私 |

## 与 RFP V1/V2 的关系（显式优势声明）

RFP V1 接受"可信发牌者 + STARK 证明"（公平性达标、发牌者全知）；
V2 才是 mental poker。**我们直接交付 V2 级引擎**（无 trusted dealer，
联合洗牌 + 证明），并把 V1 要求的 STARK 证明能力用同一条管线兑现到
结算与发牌语句的链上验证——不是降级满足 V1，而是跳过 V1 直接做 V2。

## TPS 论证（回应"1000 TPS 够吗"）

- per-action 上链在任何链都不经济（费用、延迟），RFP 也不要求；
- 本方案链上足迹 = 进出池（每玩家每 session 1–2 次）+ 每手一次
  结算/锚定 tx（~12 tx/h/桌）。1000 TPS 对应数十万桌并发，
  瓶颈根本不在 TPS；
- "公开可查"通过每手状态根承诺 + 争议 STARK + viewing key 实现，
  不需要全量数据上链。

## 诚实边界（评审信任的前提）

- 游戏执行（下注/超时/evaluator）链下由服务器驱动：证明验证与
  结算锚定上链，执行层信任是现阶段边界（roadmap：结算残差全量
  进 EC_OP 批次 → 电路重执行 → 每手 STARK 聚合）；
- 提现（unshield）合约规范已交付，实现在外部结算 workspace；
- 过渡期双曲线共存：新表 STARK 曲线、Sui 旧表 legacy BLS 收尾。
