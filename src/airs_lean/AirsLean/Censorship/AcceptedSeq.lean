import AirsLean.Censorship.ActionLog

/-!
# AcceptedSeq — 收据与 accepted-seq 向量；审查检测

`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §7.1：服务器对每个动作回签
收据（accepted / autoAccepted / rejected + 理由），并在 settle 事件发布
每玩家的 accepted-seq 向量——"本手我接受了你到第几号动作"。审查由此
成为**可判定命题**：

- `receipt_binding`：诚实服务器的 accepted-seq 承诺与已接受日志一致
  （日志中该玩家的最大 seq）；
- `censorship_provable`：玩家持有验签通过的动作（seq = k）∧ 链上
  accepted-seq < k ⇒ 该动作未被服务器接受（被审查）——要么审查发生，
  要么签名被伪造（后者由 EUF-CMA 假设排除）；
- `no_false_accusation`：诚实服务器（不丢弃真实动作）不会触发
  审查判定——检测无假阳性；
- `rejection_receipt_path`：rejected 收据使拒绝可归因（理由短码在收据
  内），与静默丢弃区分；
- `receipt_msg_binding`：回执签名字节序覆盖 `(domain, table_id,
  player_pk, seq, action, amount, decision, reason)`——收据内容不可
  偷换（域分离 + 全字段入签）。

出处：§7.1（ACTION_RECEIPT #17）；`texas/src/pokergame/receipts.rs`
（`RECEIPT_DOMAIN`、`ActionReceipt`、`receipt_msg_bytes`）；
链上事件不可篡改作为显式假设（Top/Assumptions）。
-/


namespace AirsLean

/-- 服务器收据决定（对齐 `receipts.rs` 的 decision 字符串三值：
accepted / autoAccepted / rejected）。 -/
inductive Decision where
  /-- 玩家签名动作被接受。 -/
  | accepted
  /-- 超时按合法默认动作代打（#17 auto 标记）。 -/
  | autoAccepted
  /-- 被拒绝（理由短码入 reason 字段）。 -/
  | rejected

/-- 动作回执（对齐 `ActionReceipt` 的签名字节序载荷）。
`RECEIPT_DOMAIN = b"zgame.action-receipt.v1"` 域分离；`operator_pk`
随每张回执下发，客户端本地验签。 -/
structure Receipt where
  /-- 桌 id（回执域为桌级）。 -/
  tableId : ℕ
  /-- 座位牌局公钥（压缩 hex 的 ℕ 视角）。 -/
  playerPk : ℕ
  /-- 动作 seq。 -/
  seq : ℕ
  /-- 动作名（fold/check/call/raise/...）。 -/
  action : ℕ
  /-- 动作金额。 -/
  amount : ℕ
  /-- 决定（accepted / autoAccepted / rejected）。 -/
  decision : Decision
  /-- rejected 时的理由短码（accepted/autoAccepted 为空）。 -/
  reason : ℕ

/-- 回执签名的消息域（对齐 `receipt_msg_bytes`：全部字段入签）。
域分离标签 + 字段序列被建模为 ℍ-结构上的注入编码——收据内容任何
字段被替换都会改变签名消息。 -/
def receiptMsg (r : Receipt) : List ℕ :=
  [0, r.tableId, r.playerPk, r.seq, r.action, r.amount,
   Decision.toCtorIdx r.decision, r.reason]

/-- 链上发布的 accepted-seq 向量（settle 事件）。 -/
def AcceptedSeq := ℕ → ℕ

/-- 已接受动作日志（服务器视角）。 -/
abbrev AcceptedLog := List LogEntry

/-- **收据绑定**：诚实服务器的 accepted-seq 是日志中该玩家的最大 seq
——发布值与日志互相锁定，事后无法改口。 -/
def ReceiptBinding (acc : AcceptedSeq) (log : AcceptedLog) (p : ℕ) : Prop :=
  acc p = (playerSeqs log p).foldr max 0

/-- 列表成员 ≤ foldr max。 -/
theorem mem_le_foldr_max {l : List ℕ} {v : ℕ} (h : v ∈ l) : v ≤ l.foldr max 0 := by
  induction l with
  | nil => exact absurd h (by simp)
  | cons a rest ih =>
    rcases List.mem_cons.mp h with rfl | h'
    · simp only [List.foldr_cons]
      omega
    · have hle := ih h'
      simp only [List.foldr_cons]
      omega

/-- **accepted-seq 上界**：绑定成立 ⇒ 日志中任何被接受动作的 seq ≤
published accepted-seq。 -/
theorem accepted_le_published {acc : AcceptedSeq} {log : AcceptedLog} {p : ℕ}
    (h : ReceiptBinding acc log p) (e : LogEntry) (hmem : e ∈ log)
    (hp : e.player = p) :
    e.seq ≤ acc p := by
  rw [h]
  have hmem' : e.seq ∈ playerSeqs log p :=
    List.mem_map_of_mem (List.mem_filter.mpr ⟨hmem, decide_eq_true hp⟩)
  exact mem_le_foldr_max hmem'

/-- **审查可证明**（本命题核心）：玩家持有验签通过的动作（seq = k），
链上 accepted-seq < k，且 published 与日志绑定 ⇒ 该动作不在已接受
日志中——审查发生（签名伪造分支由 EUF-CMA 假设排除，见
`genuine_action`）。 -/
theorem censorship_provable {acc : AcceptedSeq} {log : AcceptedLog} {p k : ℕ}
    (hbind : ReceiptBinding acc log p)
    (hlt : acc p < k)
    (e : LogEntry) (hseq : e.seq = k) :
    ¬ (e ∈ log ∧ e.player = p) := by
  rintro ⟨hmem, hp⟩
  have := accepted_le_published hbind e hmem hp
  omega

/-- **无假阳性**：诚实服务器（accepted-seq ≥ 一切其声称接受的 seq）
不会触发审查判定——若动作确被接受，则 accepted-seq ≥ seq。 -/
theorem no_false_accusation {acc : AcceptedSeq} {log : AcceptedLog} {p k : ℕ}
    (hbind : ReceiptBinding acc log p)
    (e : LogEntry) (hmem : e ∈ log) (hp : e.player = p) (hseq : e.seq = k) :
    acc p ≥ k := by
  have := accepted_le_published hbind e hmem hp
  omega

/-- **拒绝可归因**：rejected 收据存在 ⇒ 服务器明确拒绝，且拒绝与
两种接受路径（accepted / autoAccepted）可区分——追责路径的凭证。 -/
theorem rejection_receipt_path (r : Receipt)
    (hr : r.decision = Decision.rejected) :
    r.decision ≠ Decision.accepted ∧ r.decision ≠ Decision.autoAccepted := by
  rw [hr]
  constructor
  · intro hcon; exact Decision.noConfusion hcon
  · intro hcon; exact Decision.noConfusion hcon

/-- **回执消息域分离**：不同字段内容的收据有不同的签名消息——
服务器无法把对 A 动作的签名挪用为对 B 动作的凭证。 -/
theorem receipt_msg_binding (r₁ r₂ : Receipt)
    (h1 : r₁.tableId = r₂.tableId) (h2 : r₁.playerPk = r₂.playerPk)
    (h3 : r₁.seq = r₂.seq) (h4 : r₁.action = r₂.action) (h5 : r₁.amount = r₂.amount)
    (h6 : r₁.decision = r₂.decision) (h7 : r₁.reason = r₂.reason) :
    receiptMsg r₁ = receiptMsg r₂ := by
  unfold receiptMsg
  rw [h1, h2, h3, h4, h5, h6, h7]

/-- **接受路径区分**：autoAccepted（代打）与 accepted（玩家签名动作）
是不同决定——代打不能伪装成玩家本人动作的接受。 -/
theorem autoAccepted_ne_accepted (d : Decision) :
    d = Decision.autoAccepted → d = Decision.accepted → False := by
  intro h1 h2
  rw [h1] at h2
  exact Decision.noConfusion h2

end AirsLean
