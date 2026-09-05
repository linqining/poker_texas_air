import AirsLean.Foundations.TraceModel

/-!
# CommonColumns — 通用列与桌面状态模型的 soundness

每个 method AIR 的 trace 由 37 个通用列 + 业务列组成
（`src/airs/common.rs`）。通用列承载：method kind one-hot selector、
pre/post state root 投影、`(table_id, hand_id, call_seq, version)` 作用域
绑定。canonical AIR 用 16-bit limb 对表达 `call_seq`/`version` 并约束
`post = pre + 1`。

本文件建立：

- `SeatImage` / `TableImage`：桌面业务状态的 ℕ 镜像（后续 Soundness /
  Custody 共用；对应 `texas` VM 的 `Seat` / `TableState`）；
- `CommonSat`：通用列约束（one-hot、limb range、`call_seq`/`version`
  递增、作用域绑定到验证者信任的 statement）；
- 定理：
  - `call_seq_progresses`：`post_call_seq = pre_call_seq + 1`（含 16-bit
    回绕安全，由 F2/F3 的 limb 桥保证）；
  - `version_bumps`：`post_version = pre_version + 1`；
  - `kind_unique`：transition kind 恰好一个 selector 命中；
  - `scope_binding`：trace 行的作用域被钉死在 statement 声明的
    `(table, hand)` 上——行不可被搬到别的桌/手；
  - `no_all_padding_trace`：全 padding trace 不满足 CommonSat——
    padding 无法伪造一次合法转移。

出处：`src/airs/common.rs:24-57`；`src/texas_canonical_air.rs`（9 个
预处理列、call_seq 16-bit rollover）；`TEXAS_TAGGED_AIR.md` "The verifier
reconstructs nine fixed preprocessed columns…"。
-/

namespace AirsLean

/-! ### 桌面状态镜像（ℕ 语义） -/

/-- 座位生命周期（对齐 VM 的 `SeatStatus`）。 -/
inductive Lifecycle where
  /-- 空位。 -/
  | empty
  /-- 已入座等待开局（等待大盲）。 -/
  | waiting
  /-- 本手参与中。 -/
  | active
  /-- 已弃牌（仍保留筹码，等待结算）。 -/
  | folded
  /-- 已离桌（结算后）。 -/
  | out

/-- 座位的资金与生命周期镜像。 -/
structure SeatImage where
  /-- 可用筹码。 -/
  stack : ℕ
  /-- 本轮已入注（未被收注）。 -/
  bet : ℕ
  /-- 本手累计入注。 -/
  totalBet : ℕ
  /-- 待生效加购（addon，下一手生效）。 -/
  pendingAddon : ℕ
  /-- 生命周期。 -/
  lifecycle : Lifecycle
  /-- 本轮是否已行动。 -/
  acted : Bool

/-- 桌面状态镜像（九座固定，对齐 `COMPOSITION_SEATS = 9`）。 -/
structure TableImage where
  /-- 九个座位。 -/
  seats : Fin 9 → SeatImage
  /-- 当前底池（已收注）。 -/
  pot : ℕ
  /-- 桌台托管总量（TableVault）。 -/
  chipPool : ℕ
  /-- 当前行动座位。 -/
  currentTurn : ℕ
  /-- 当前下注额（本轮最高入注）。 -/
  currentBet : ℕ
  /-- 最小加注增量。 -/
  minRaise : ℕ

/-! ### 通用列约束 -/

/-- method kind 的 selector 数（canonical 0..=28）。 -/
def NumKinds : ℕ := 29

/-- 作用域 statement：验证者独立信任的 `(table, hand)` 绑定。 -/
structure Scope where
  /-- 桌 id。 -/
  table : ℕ
  /-- 手序号。 -/
  hand : ℕ

/-- 通用列 witness：M31 limb 列 + selector 家族 + call_seq/version 进位。 -/
structure CommonWitness where
  /-- method kind one-hot selectors。 -/
  methodKind : Fin NumKinds → M31
  /-- table id 的 4-limb 编码。 -/
  tableId : Limbs
  /-- hand id（host 侧保证 < 2^16 的 M31 标量列）。 -/
  handId : M31
  /-- pre/post call seq 的 limb 对（canonical 预处理列）。 -/
  preCallSeq : Limbs
  postCallSeq : Limbs
  /-- call_seq 加一的 3 个进位 witness。 -/
  seqCarry : AddCarry
  /-- pre/post version 的 limb 对。 -/
  preVersion : Limbs
  postVersion : Limbs
  /-- version 加一的 3 个进位 witness。 -/
  verCarry : AddCarry

/-- 通用列约束。`stmt` 是验证者从 L1 任务重建的 statement 作用域；
`seqOne`/`verOne` 是常数 1 的 limb 编码（AIR 常数列）。 -/
def CommonSat (w : CommonWitness) (stmt : Scope)
    (seqOne verOne : Limbs) (seqOneV verOneV : ℕ) : Prop :=
  OneHotSel w.methodKind ∧
  decode w.tableId = stmt.table ∧
  w.handId.val = stmt.hand ∧
  AddSat w.preCallSeq seqOne w.postCallSeq w.seqCarry.c0 w.seqCarry.c1 w.seqCarry.c2 ∧
  AddSat w.preVersion verOne w.postVersion w.verCarry.c0 w.verCarry.c1 w.verCarry.c2 ∧
  decode seqOne = seqOneV ∧ decode verOne = verOneV ∧
  seqOneV = 1 ∧ verOneV = 1

/-- **call_seq 单调**：约束成立 ⇒ 该行 `post_call_seq = pre_call_seq + 1`。
行不可被回放（重放旧 seq 的行不满足递增约束），也不可跳号。 -/
theorem call_seq_progresses (w : CommonWitness) (stmt : Scope)
    (seqOne verOne : Limbs) (seqOneV verOneV : ℕ)
    (h : CommonSat w stmt seqOne verOne seqOneV verOneV) :
    decode w.postCallSeq = decode w.preCallSeq + 1 := by
  obtain ⟨_, _, _, hseq, _, hs1, _, hs3, _⟩ := h
  have h9 := add_sat_sound' hseq
  rw [hs1, hs3] at h9
  omega

/-- **version 递增**：约束成立 ⇒ `post_version = pre_version + 1`。 -/
theorem version_bumps (w : CommonWitness) (stmt : Scope)
    (seqOne verOne : Limbs) (seqOneV verOneV : ℕ)
    (h : CommonSat w stmt seqOne verOne seqOneV verOneV) :
    decode w.postVersion = decode w.preVersion + 1 := by
  obtain ⟨_, _, _, _, hver, _, hs2, _, hs4⟩ := h
  have h9 := add_sat_sound' hver
  rw [hs2, hs4] at h9
  omega

/-- **kind 唯一**：one-hot selector 恰好命中一个 transition kind。
prover 无法让一行同时声称两种转移，也无法声称零种。 -/
theorem kind_unique (w : CommonWitness) (stmt : Scope)
    (seqOne verOne : Limbs) (seqOneV verOneV : ℕ)
    (h : CommonSat w stmt seqOne verOne seqOneV verOneV) :
    ∃! i : Fin NumKinds, w.methodKind i = 1 :=
  one_hot_unique _
    (show NumKinds < 2147483647 from by rw [show NumKinds = 29 from rfl]; norm_num) h.1

/-- **作用域绑定**：约束成立 ⇒ 该行的 `(table, hand)` 与 statement 声明
一致。行不能被搬到别的桌/手/序号——这是防跨手重放的 trace 层根基。 -/
theorem scope_binding (w : CommonWitness) (stmt : Scope)
    (seqOne verOne : Limbs) (seqOneV verOneV : ℕ)
    (h : CommonSat w stmt seqOne verOne seqOneV verOneV) :
    decode w.tableId = stmt.table ∧ w.handId.val = stmt.hand := by
  obtain ⟨_, h1, h2, _, _, _, _, _, _⟩ := h
  exact ⟨h1, h2⟩

/-- **全 padding trace 不满足约束**：若每一行都是 padding 行（除 padding
标志外全零），则 selector 全零，one-hot 求和为 0 ≠ 1——padding 无法伪造
一次合法转移。这是 `no_all_padding_trace` 的 selector 侧。 -/
theorem no_all_padding_trace (w : CommonWitness) (stmt : Scope)
    (seqOne verOne : Limbs) (seqOneV verOneV : ℕ)
    (hpad : ∀ i : Fin NumKinds, w.methodKind i = 0) :
    ¬ CommonSat w stmt seqOne verOne seqOneV verOneV := by
  rintro ⟨hsum, -⟩
  unfold OneHotSel at hsum
  obtain ⟨hsum, -⟩ := hsum
  have hz : (∑ i : Fin NumKinds, w.methodKind i) = 0 :=
    Finset.sum_eq_zero (fun i _ => hpad i)
  rw [hz] at hsum
  norm_num at hsum

end AirsLean
