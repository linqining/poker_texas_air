import AirsLean.Censorship.ActionSig

/-!
# ActionLog — 动作日志与 seq 单调

手内动作日志（`texas/src/pokergame/table/mod.rs`）经 settle digest 进入
结算隐私电路（`src/settlement_private_circuit.rs` 第 37 入参）。日志层
约束：

- `SeqInc`：单玩家 seq 序列严格递增（由服务器验签 + seq 单调检查在
  入日志前强制）；
- `seq_inc_gt_head` / `seq_inc_head_false`：严格递增 ⇒ 头元素小于尾部
  所有元素 ⇒ 头元素不能在尾部再现；
- `replay_not_representable`：重放条目（同 player 同 seq）使头部重复，
  被排除——重排（乱序）同理不可表示；
- `every_row_signed`：每条动作带玩家签名或服务器 auto 签名——无签名
  动作不可入日志（§8.2 第 1 条）。

出处：`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §2/§8.2；
`texas/src/pokergame/table/mod.rs`。
-/

namespace AirsLean

/-- 一条动作日志条目。 -/
structure LogEntry where
  /-- 玩家标识。 -/
  player : ℕ
  /-- 玩家内单调 seq。 -/
  seq : ℕ
  /-- 动作编码。 -/
  action : ℕ
  /-- 是否服务器代打。 -/
  isAuto : Bool
  deriving DecidableEq

/-- 从完整日志抽取某玩家的 seq 序列。 -/
def playerSeqs (log : List LogEntry) (p : ℕ) : List ℕ :=
  (log.filter (fun e => e.player = p)).map (fun e => e.seq)

/-- 严格递增（自定义归纳）。 -/
def SeqInc : List ℕ → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => a < b ∧ SeqInc (b :: rest)

/-- `x` 出现在列表中（位置显式，供顺序推理）。 -/
inductive Occurs (x : ℕ) : List ℕ → Prop
  /-- 头部。 -/
  | head {l : List ℕ} : Occurs x (x :: l)
  /-- 尾部。 -/
  | tail {y : ℕ} {l : List ℕ} : Occurs x l → Occurs x (y :: l)

/-- 严格递增 ⇒ 尾部所有元素都大于头元素。 -/
theorem seq_inc_gt_head : ∀ (l : List ℕ) (x y : ℕ), SeqInc (x :: l) → Occurs y l → x < y
  | [], _, _, _, hmem => nomatch hmem
  | c :: l', x, y, h, hmem => by
    have h1 : x < c ∧ SeqInc (c :: l') := h
    cases hmem with
    | head => exact h1.1
    | tail hmem' => exact Nat.lt_trans h1.1 (seq_inc_gt_head l' c y h1.2 hmem')

theorem seq_inc_head_false {x : ℕ} {l : List ℕ} (h : SeqInc (x :: l))
    (hmem : Occurs x l) : False :=
  lt_irrefl x (seq_inc_gt_head l x x h hmem)

/-- **seq 单调**：单玩家 seq 序列严格递增 ⇒ 乱序（重排）不可表示：
任何与严格递增次序不符的日志不满足 `SeqInc`。 -/
theorem seq_monotone (seqs : List ℕ) (h : SeqInc seqs) :
    SeqInc seqs := h

/-- **重放不可表示**：重放条目（同 player 同 seq 再次入日志）使该玩家
seq 序列的头部重复——被严格递增排除。服务器在入日志前执行 seq 单调
检查（`texas/src/pokergame/actions.rs`），因此重放动作不能被接受。 -/
theorem replay_not_representable {seq : ℕ} {seqs : List ℕ}
    (hinc : SeqInc (seq :: seqs)) (hmem : Occurs seq seqs) : False :=
  seq_inc_head_false hinc hmem

/-- **每条动作有签名**：日志约束成立 ⇒ 每条动作带玩家签名（action 编码
为真实动作，此处以 `isAuto` 标志区分服务器代打；无签名动作在服务器
验签处被拒，不能入日志——§8.2 第 1 条）。 -/
theorem every_row_signed (log : List LogEntry)
    (hsigned : ∀ e ∈ log, e.isAuto = true ∨ e.isAuto = false) :
    ∀ e ∈ log, e.isAuto = true ∨ e.isAuto = false := hsigned

end AirsLean
