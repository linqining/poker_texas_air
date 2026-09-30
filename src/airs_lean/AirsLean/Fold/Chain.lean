import Mathlib

/-!
# Chain — acc 链与批折叠的绑定性（属性 P1 / P4）

牌桌折叠协议（fold_batch 设计，见任务书「■ 每手承诺进 acc 链：零新公式」）把
每手的 claim 词折叠进累加链：

* 折叠步 `acc' = H([acc] ++ claims)` —— 宿主/电路逐 felt 公式
  `recurse.rs:60-65`（`fold_accumulator` = `poseidon_hash_many([prev_acc] ++ claims)`）；
* combined 公开段 fact：`chain.rs:206-211`（`combined_expected_fact` =
  `poseidon_hash_many([program_hash ‖ 16 词输出])`，合约 `fact_for_segment`
  `poker_dual_settlement.cairo:302-306` 同式）;
* 批链 `batch_fact_n = poseidon([aph ‖ 根输出 8 felts ‖ acc_{n-1} ‖ 根hi ‖ 根lo])`
  （`chain.rs:462-477` `derive_batch_fact` / `settlement_batch_private.cairo:231-241`）；
* keccak 批根叶 = `keccak(index ‖ ph ‖ binding ‖ fact)`（`batch.rs:96-105`）。

**模型与假设（如实声明）**：`H : List F → F` 是 poseidon 吸收的抽象模型；
本文件的一切定理都以 **H 单射** 为前提假设（Hypothesis H1）。poseidon 的
（预像）抗碰撞性是密码学假设，Lean 无法也不应从置换定义推出——该假设在
FormalVerdict 的 gaps 里单独标注。机器可证的命题是：*给定* H1，折叠映射
在其全部输入（prev + claims 词表 + 词序）上单射，即：

1. (P1) 折叠输出相等 ⇒ prev 与 claims 逐词相等 ⇒ 链终值绑定全部历史
   `(acc_i, claims_i)`；
2. (P4) 重排/换批拼接/篡改任一 claim 词必改折叠输出；keccak 批根叶内嵌
   `index ‖ ph ‖ binding ‖ fact` 四元组 ⇒ 批根绑定有序语句表
   （跨手重组必改根，与 chain.rs:695-712 `combined_chain_acc_is_fact_bound`
   与 chain.rs:633-637 序敏感负例同一机制的抽象形式）。
-/

namespace AirsLean.Fold.Chain

variable {F : Type*} [DecidableEq F]

/-- 列表尾段消去：`c1 ++ c2 = c1 ++ c2' → c2 = c2'`。 -/
theorem append_right_cancel {c1 c2 c2' : List F} (h : c1 ++ c2 = c1 ++ c2') :
    c2 = c2' := by
  induction c1 with
  | nil => exact h
  | cons x l ih =>
    exact ih (by simpa using h)

/-- 列表 map 消去：f 单射 ⇒ `map f l = map f l' → l = l'`。 -/
theorem map_cancel {α : Type*} [DecidableEq α] {β : Type*} {f : α → β}
    (hf : Function.Injective f) :
    ∀ l l' : List α, l.map f = l'.map f → l = l' := by
  intro l
  induction l with
  | nil =>
    intro l' h
    cases l' with
    | nil => rfl
    | cons a tl => simp at h
  | cons a tl ih =>
    intro l' h
    cases l' with
    | nil => simp at h
    | cons a' tl' =>
      simp only [List.map_cons] at h
      obtain ⟨h1, h2⟩ : f a = f a' ∧ tl.map f = tl'.map f := by simpa using h
      rw [hf h1, ih tl' h2]

/-- 折叠步：`acc' = H([acc] ++ claims)`。
    公式出处：`recurse.rs:60-65`（`fold_accumulator`）。 -/
def fold (H : List F → F) (prev : F) (claims : List F) : F :=
  H (prev :: claims)

/-- **P1（绑定性核心）**：H 单射 ⇒ 折叠映射在其全部输入上单射：
    折叠输出相等 ⇔ (prev, claims) 逐词相等。 -/
theorem fold_eq_iff (H : List F → F) (hH : Function.Injective H)
    {a a' : F} {c c' : List F} :
    fold H a c = fold H a' c' ↔ a = a' ∧ c = c' := by
  constructor
  · intro h
    have h' := hH h
    simpa using h'
  · rintro ⟨rfl, rfl⟩
    rfl

/-- P1 推论：篡改 prev 必改折叠（对偶 `recurse.rs:485-499` run_negative_wrong_prev）。 -/
theorem fold_inj_prev (H : List F → F) (hH : Function.Injective H)
    {a a' : F} {c : List F} (h : fold H a c = fold H a' c) : a = a' :=
  (fold_eq_iff H hH).mp h |>.1

/-- P1 推论：篡改任一 claim 词必改折叠。 -/
theorem fold_inj_claims (H : List F → F) (hH : Function.Injective H)
    {a : F} {c c' : List F} (h : fold H a c = fold H a c') : c = c' :=
  (fold_eq_iff H hH).mp h |>.2

/-- **P4（顺序敏感）**：相邻两 claim 换序必改折叠。
    真实例即 `poseidon_hash_many` 输入序（chain.rs:633-637 序敏感断言的抽象形式）。 -/
theorem fold_swap_ne (H : List F → F) (hH : Function.Injective H)
    {a x y : F} {r : List F} (hxy : x ≠ y) :
    fold H a (x :: y :: r) ≠ fold H a (y :: x :: r) := by
  intro heq
  obtain ⟨-, hc⟩ := (fold_eq_iff H hH).mp heq
  have h2 : x = y ∧ y = x := by simpa using hc
  exact hxy h2.1

/-- **P4（跨批拼接不可行）**：claims 尾段不同 ⇒ 折叠不同——
    把别桌/别手的 claim 段拼进本批必改折叠输出。 -/
theorem fold_append_ne (H : List F → F) (hH : Function.Injective H)
    {a : F} {c1 c2 c2' : List F} (h : c2 ≠ c2') :
    fold H a (c1 ++ c2) ≠ fold H a (c1 ++ c2') := by
  intro heq
  exact h (append_right_cancel ((fold_eq_iff H hH).mp heq).2)

/-- 手级链：`acc_{i+1} = fold(acc_i, claims_i)`（chain.rs 累加链的纯模型，
    `acc_0 = genesis`）。 -/
def chain (H : List F → F) : F → List (List F) → F
  | a, [] => a
  | a, c :: cs => chain H (fold H a c) cs

/-- **P1（链历史唯一 / 绑定性）**：等长链的终值相等 ⇒ 整条历史逐词相等：
    终态 acc 唯一决定每步的 (acc_i, claims_i)——篡改任一历史词必改终值
    （`chain.rs:848-888` accumulator_chain_links 负例族的抽象定理）。 -/
theorem chain_history_unique (H : List F → F) (hH : Function.Injective H) :
    ∀ (cs cs' : List (List F)) (a a' : F), cs.length = cs'.length →
      chain H a cs = chain H a' cs' → a = a' ∧ cs = cs' := by
  intro cs
  induction cs with
  | nil =>
    intro cs' a a' hlen heq
    cases cs' with
    | nil =>
      simp only [chain] at heq
      exact ⟨heq, rfl⟩
    | cons c' tl => simp at hlen
  | cons c tl ih =>
    intro cs' a a' hlen heq
    cases cs' with
    | nil => simp at hlen
    | cons c' tl' =>
      obtain ⟨hfold, htl⟩ := ih tl' (fold H a c) (fold H a' c')
        (by simpa using hlen) heq
      obtain ⟨ha, hc⟩ := (fold_eq_iff H hH).mp hfold
      exact ⟨ha, by rw [hc, htl]⟩

section BatchRoot

variable {G : Type*} [DecidableEq G]

/-- keccak 批根叶四元组：`(index, program_hash, hand_binding, fact)`
    （`batch.rs:96-105`：`leaf_i = keccak256(index_be32 ‖ ph ‖ binding ‖ fact)`；
    index 置于首位 ⇒ 语句位置进预映像）。 -/
abbrev Leaf4 (G : Type*) := G × G × G × G

/-- 叶四元组摊平进预映像。 -/
def leaf4 (t : Leaf4 G) : List G := [t.1, t.2.1, t.2.2.1, t.2.2.2]

/-- 叶编码单射：四元组与其摊平词表一一对应。 -/
theorem leaf4_inj {t t' : Leaf4 G} : leaf4 t = leaf4 t' ↔ t = t' := by
  obtain ⟨a, b, c, d⟩ := t
  obtain ⟨a', b', c', d'⟩ := t'
  constructor
  · intro h
    simp only [leaf4, List.cons.injEq, and_true] at h
    obtain ⟨rfl, rfl, rfl, rfl⟩ := h
    rfl
  · intro h; rw [h]

/-- 批根模型：`root = H(K × 叶哈希)`。keccak 两两折叠的绑定结论只依赖
    「有序叶集合进单射哈希」这一形状，二叉折叠的中间词不新增输入自由度
    （叶哈希序列不同 ⇒ 折叠树输入不同 ⇒ 根不同）。 -/
def batchRoot (H : List G → G) (ts : List (Leaf4 G)) : G :=
  H (ts.map (fun t => H (leaf4 t)))

/-- **P4（批根绑定有序语句表）**：H 单射 ⇒ 批根单射于 `(index, ph, binding, fact)`
    的有序表——重排（index 位变）、换 binding、换 fact、跨批拼叶必改根。
    （`chain.rs:633-637` swapped_root 断言与 `SettleBatch.sol` index 叶的抽象形式。） -/
theorem batchRoot_inj (H : List G → G) (hH : Function.Injective H) :
    Function.Injective (batchRoot H) := by
  intro ts ts' heq
  have h1 : ts.map (fun t => H (leaf4 t)) = ts'.map (fun t => H (leaf4 t)) := hH heq
  have hmap : Function.Injective (fun t : Leaf4 G => H (leaf4 t)) :=
    fun a b hab => leaf4_inj.mp (hH hab)
  exact map_cancel hmap ts ts' h1

end BatchRoot

end AirsLean.Fold.Chain
