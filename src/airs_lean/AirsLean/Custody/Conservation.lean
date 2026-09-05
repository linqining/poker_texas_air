import AirsLean.Custody.ChipState

/-!
# Conservation — 托管守恒不变量

对每个被 AIR 接受的转移类，托管总量 `custodyTotal` 满足：

- 非资金转移（fold/check/call/bet/raise/advance_round/force_fold/kick）：
  **不变**——筹码只在托管内部移动（座位间移动或 bet→pot 收注）；
- 资金存入（join/rebuy/addon）：**恰好 +amount**——唯一的托管递增入口；
- 支出（leave 退款 / settlement 支付）：**恰好 −amount**——唯一的托管
  递减出口，且金额由 AIR 精确锁定（S4/S5）。

`conservation_seq`：任意被 AIR 接受的转移序列满足
`custodyTotal_final + Σ payouts = custodyTotal_initial + Σ deposits`。

出处：`src/airs/actions/`、`src/airs/funds/`、`src/airs/lifecycle/`、
`src/airs/composition/`（各 method AIR 的资金约束）。
-/

namespace AirsLean

/-- 一步转移的类别：非资金转移 / 存入 / 支出。参数 `amt` 是 AIR 从
limb 约束解码出的精确金额。 -/
inductive Step where
  /-- 非资金转移（fold/check/call/bet/raise/advance_round/force_fold/kick）。 -/
  | idle : Step
  /-- 资金存入（join/rebuy/addon）。 -/
  | funding : ℕ → Step
  /-- 支出（leave 退款 / settlement 支付）。 -/
  | payout : ℕ → Step

/-- 一步转移的场级 AIR 语义（由对应 method AIR 的 Sat 定理解码而来）：

- `idle`：stack 总和不变、pending 总和不变、`pot + Σ bet` 不变、
  chip_pool 不变；
- `funding amt`：座位字段不变、chip_pool 恰好 +amt；
- `payout amt`：座位字段不变、chip_pool 恰好 −amt（ amt ≤ chip_pool）。 -/
def StepRel (k : Step) (s t : TableImage) : Prop :=
  match k with
  | Step.idle =>
      (∑ p, (t.seats p).stack) = (∑ p, (s.seats p).stack) ∧
      (∑ p, (t.seats p).pendingAddon) = (∑ p, (s.seats p).pendingAddon) ∧
      t.pot + (∑ p, (t.seats p).bet) = s.pot + (∑ p, (s.seats p).bet) ∧
      t.chipPool = s.chipPool
  | Step.funding amt =>
      (∀ p, (t.seats p).stack = (s.seats p).stack ∧
        (t.seats p).bet = (s.seats p).bet ∧
        (t.seats p).pendingAddon = (s.seats p).pendingAddon) ∧
      t.pot = s.pot ∧
      t.chipPool = s.chipPool + amt
  | Step.payout amt =>
      (∀ p, (t.seats p).stack = (s.seats p).stack ∧
        (t.seats p).bet = (s.seats p).bet ∧
        (t.seats p).pendingAddon = (s.seats p).pendingAddon) ∧
      t.pot = s.pot ∧
      s.chipPool = t.chipPool + amt

/-- **单步守恒（idle）**：非资金转移不改变托管总量。 -/
theorem conservation_idle {s t : TableImage}
    (h : StepRel Step.idle s t) : custodyTotal t = custodyTotal s := by
  obtain ⟨hst, hpd, hpb, hpool⟩ := h
  unfold custodyTotal
  omega

/-- **单步存入**：funding 使托管总量恰好 +amt（唯一递增入口）。 -/
theorem conservation_funding {s t : TableImage} {amt : ℕ}
    (h : StepRel (Step.funding amt) s t) :
    custodyTotal t = custodyTotal s + amt := by
  obtain ⟨hseats, hpot, hpool⟩ := h
  unfold custodyTotal
  have hst : (∑ p, (t.seats p).stack) = (∑ p, (s.seats p).stack) :=
    Finset.sum_congr rfl fun p _ => (hseats p).1
  have hbt : (∑ p, (t.seats p).bet) = (∑ p, (s.seats p).bet) :=
    Finset.sum_congr rfl fun p _ => (hseats p).2.1
  have hpd : (∑ p, (t.seats p).pendingAddon) = (∑ p, (s.seats p).pendingAddon) :=
    Finset.sum_congr rfl fun p _ => (hseats p).2.2
  omega

/-- **单步支出**：payout 使托管总量恰好 −amt（唯一递减出口）。 -/
theorem conservation_payout {s t : TableImage} {amt : ℕ}
    (h : StepRel (Step.payout amt) s t) :
    custodyTotal t + amt = custodyTotal s := by
  obtain ⟨hseats, hpot, hpool⟩ := h
  unfold custodyTotal
  have hst : (∑ p, (t.seats p).stack) = (∑ p, (s.seats p).stack) :=
    Finset.sum_congr rfl fun p _ => (hseats p).1
  have hbt : (∑ p, (t.seats p).bet) = (∑ p, (s.seats p).bet) :=
    Finset.sum_congr rfl fun p _ => (hseats p).2.1
  have hpd : (∑ p, (t.seats p).pendingAddon) = (∑ p, (s.seats p).pendingAddon) :=
    Finset.sum_congr rfl fun p _ => (hseats p).2.2
  omega

/-- 转移序列的关系：每一步被 AIR 接受。 -/
def StepChain (steps : List Step) (s t : TableImage) : Prop :=
  match steps with
  | [] => t = s
  | k :: rest => ∃ mid, StepRel k s mid ∧ StepChain rest mid t

/-- 序列的总存入/总支出。 -/
def totalDeposit (steps : List Step) : ℕ :=
  match steps with
  | [] => 0
  | Step.funding amt :: rest => amt + totalDeposit rest
  | _ :: rest => totalDeposit rest

def totalPayout (steps : List Step) : ℕ :=
  match steps with
  | [] => 0
  | Step.payout amt :: rest => amt + totalPayout rest
  | _ :: rest => totalPayout rest

/-- **序列守恒**（本命题核心）：任意被 AIR 接受的转移序列满足
`custodyTotal_final + Σ payouts = custodyTotal_initial + Σ deposits`。
筹码不生不灭，只在托管内部移动或经 AIR 锁定金额的出入口穿越边界。 -/
theorem conservation_seq (steps : List Step) (s t : TableImage)
    (h : StepChain steps s t) :
    custodyTotal t + totalPayout steps = custodyTotal s + totalDeposit steps := by
  induction steps generalizing s with
  | nil =>
    have hEq : t = s := h
    subst hEq
    unfold totalPayout totalDeposit
    omega
  | cons k rest ih =>
    rcases k with _ | amt | amt
    · have hE : ∃ mid, StepRel Step.idle s mid ∧ StepChain rest mid t := h
      obtain ⟨mid, hstep, hrest⟩ := hE
      have h1 := conservation_idle hstep
      have h2 := ih mid hrest
      unfold totalPayout totalDeposit
      omega
    · have hE : ∃ mid, StepRel (Step.funding amt) s mid ∧ StepChain rest mid t := h
      obtain ⟨mid, hstep, hrest⟩ := hE
      have h1 := conservation_funding hstep
      have h2 := ih mid hrest
      unfold totalPayout totalDeposit
      omega
    · have hE : ∃ mid, StepRel (Step.payout amt) s mid ∧ StepChain rest mid t := h
      obtain ⟨mid, hstep, hrest⟩ := hE
      have h1 := conservation_payout hstep
      have h2 := ih mid hrest
      unfold totalPayout totalDeposit
      omega

end AirsLean
