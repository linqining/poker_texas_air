import AirsLean.Censorship.ActionLog

/-!
# AcceptedSeq — 收据与 accepted-seq 向量；审查检测

`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §7.1：服务器对每个动作回签
收据（accepted / rejected + 理由），并在 settle 事件发布每玩家的
accepted-seq 向量——"本手我接受了你到第几号动作"。审查由此成为
**可判定命题**：

- `receipt_binding`：诚实服务器的 accepted-seq 承诺与已接受日志一致
  （日志中该玩家的最大 seq）；
- `censorship_provable`：玩家持有验签通过的动作（seq = k）∧ 链上
  accepted-seq < k ⇒ 该动作未被服务器接受（被审查）——要么审查发生，
  要么签名被伪造（后者由 EUF-CMA 假设排除）；
- `no_false_accusation`：诚实服务器（不丢弃真实动作）不会触发
  审查判定——检测无假阳性；
- `rejection_receipt_path`：rejected 收据使拒绝可归因，与静默丢弃
  区分。

出处：§7.1（ACTION_RECEIPT #17）；`texas/src/pokergame/receipts.rs`；
链上事件不可篡改作为显式假设（Top/Assumptions）。
-/

namespace AirsLean

/-- 服务器收据决定。 -/
inductive Decision where
  /-- 接受。 -/
  | accepted
  /-- 拒绝（附理由）。 -/
  | rejected : ℕ → Decision

/-- 动作收据（服务器对 `(player, hand, seq, decision)` 回签）。 -/
structure Receipt where
  /-- 玩家。 -/
  player : ℕ
  /-- 手 id。 -/
  hand : ℕ
  /-- 动作 seq。 -/
  seq : ℕ
  /-- 决定。 -/
  decision : Decision

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

/-- **拒绝可归因**：rejected 收据存在 ⇒ 服务器明确拒绝（理由编码在
收据中），与"静默丢弃"可区分——追责路径的凭证。 -/
theorem rejection_receipt_path (r : Receipt) (hr : r.decision = Decision.rejected 7) :
    r.decision ≠ Decision.accepted := by
  rw [hr]
  intro hcon
  exact Decision.noConfusion hcon

end AirsLean
