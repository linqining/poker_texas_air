//! 从真实 stwo 2.3.0（crates.io 版本）导出测试向量，生成 Lean 测试文件
//! `StwoLean/Vectors.lean`。每次运行输出确定性一致（无随机源，LCG 固定种子）。
//!
//! 用法：`cargo run --release > ../StwoLean/Vectors.lean`
//!
//! 这些向量把 `StwoLean.M31/CM31/QM31/CirclePoint` 的每个算子与 Rust
//! 参考实现逐一对拍——Lean 侧是干净的数学模型，Rust 侧是位技巧优化的
//! 生产实现，两者的等价性由这些机器检验的断言钉死。
//!
//! 注意：向量数量刻意精简（每算子类别保留代表性条目）。每条 `decide`
//! 都是内核对 `ZMod (2^31-1)` 运算的完整归约，单条约需数秒，
//! 全量断言的编译时间随条目数线性增长。

use stwo::core::circle::{CirclePoint, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_GEN};
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::FieldExpOps;

/// 固定种子的 LCG，保证生成结果可复现。
struct Lcg(u64);

impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn next_m31(&mut self) -> M31 {
        M31(((self.next_u64() >> 33) as u32) % P)
    }

    fn next_cm31(&mut self) -> CM31 {
        CM31(self.next_m31(), self.next_m31())
    }

    fn next_qm31(&mut self) -> QM31 {
        QM31(self.next_cm31(), self.next_cm31())
    }
}

fn m31_lean(v: M31) -> String {
    // 显式类型标注：裸数字会被 elaborator 当作 ℕ，导致语义完全错误。
    format!("(({}) : StwoLean.M31)", v.0)
}

fn cm31_lean(v: CM31) -> String {
    format!("(StwoLean.CM31.ofU32 {} {})", v.0 .0, v.1 .0)
}

fn qm31_lean(v: QM31) -> String {
    format!(
        "(StwoLean.QM31.ofU32 {} {} {} {})",
        v.0 .0 .0, v.0 .1 .0, v.1 .0 .0, v.1 .1 .0
    )
}

fn point_lean(p: CirclePoint<M31>) -> String {
    format!("(StwoLean.CirclePoint.mk {} {})", p.x.0, p.y.0)
}

fn point_secure_lean(p: CirclePoint<QM31>) -> String {
    format!(
        "(StwoLean.CirclePoint.mk {} {})",
        qm31_lean(p.x),
        qm31_lean(p.y)
    )
}

fn main() {
    let mut rng = Lcg(0x517cc1b727220a95);

    println!("import StwoLean.M31");
    println!("import StwoLean.CM31");
    println!("import StwoLean.QM31");
    println!("import StwoLean.Circle");
    println!();
    println!("/-!");
    println!("# Vectors — 从真实 stwo 2.3.0 导出的对拍测试向量");
    println!();
    println!("**本文件由 `vector-gen` 自动生成，勿手改。**");
    println!("重新生成：`cd vector-gen && cargo run --release > ../StwoLean/Vectors.lean`。");
    println!();
    println!("每个 `example` 都是 Lean 数学模型与 Rust 生产实现（位技巧优化）");
    println!("之间的逐算子一致性断言，由内核 `decide` 机器检验。");
    println!("-/");
    println!();
    println!("namespace StwoLean.Vectors");
    println!();
    println!("section M31");

    // —— M31：边界元素与随机元素的 add/mul ——
    let m31_cases: Vec<(M31, M31)> = vec![
        (M31(0), M31(0)),
        (M31(1), M31(P - 1)),
        (M31(P - 1), M31(P - 1)),
        (M31(P - 2), M31(2)),
        (rng.next_m31(), rng.next_m31()),
    ];
    for (x, y) in &m31_cases {
        println!(
            "example : {} + {} = {} := by decide",
            m31_lean(*x),
            m31_lean(*y),
            m31_lean(*x + *y)
        );
        println!(
            "example : {} * {} = {} := by decide",
            m31_lean(*x),
            m31_lean(*y),
            m31_lean(*x * *y)
        );
    }
    // sub
    let (xs, ys) = (m31_cases[3].0, m31_cases[3].1);
    println!(
        "example : {} - {} = {} := by decide",
        m31_lean(xs),
        m31_lean(ys),
        m31_lean(xs - ys)
    );

    // —— M31 逆元（stwo `pow2147483645` 加法链）与快速幂一致性 ——
    for v in [M31(1), M31(19), M31(P - 1), rng.next_m31()] {
        let inv = v.inverse();
        println!(
            "example : {} * {} = 1 := by decide",
            m31_lean(v),
            m31_lean(inv)
        );
    }
    // Lean 侧 `fpow`（快速幂）须与 Rust 的 pow-加法链逆元一致。
    for v in [M31(19), rng.next_m31()] {
        println!(
            "example : StwoLean.fpow {} 2147483645 = {} := by decide",
            m31_lean(v),
            m31_lean(v.inverse())
        );
    }
    println!("end M31");
    println!();
    println!("section CM31");

    // —— CM31：stwo 单元测试 test_ops 的全部断言 ——
    let cm0 = CM31(M31(1), M31(2));
    let cm1 = CM31(M31(4), M31(5));
    println!(
        "example : {} + {} = {} := by decide",
        cm31_lean(cm0),
        cm31_lean(cm1),
        cm31_lean(cm0 + cm1)
    );
    println!(
        "example : {} * {} = {} := by decide",
        cm31_lean(cm0),
        cm31_lean(cm1),
        cm31_lean(cm0 * cm1)
    );
    println!(
        "example : -{} = {} := by decide",
        cm31_lean(cm0),
        cm31_lean(-cm0)
    );
    println!(
        "example : {} - {} = {} := by decide",
        cm31_lean(cm0),
        cm31_lean(cm1),
        cm31_lean(cm0 - cm1)
    );
    // stwo test_inverse：(1+2i) 的逆元乘法还原。
    println!(
        "example : {} * {} = StwoLean.CM31.ofU32 1 0 := by decide",
        cm31_lean(cm0),
        cm31_lean(cm0.inverse())
    );
    // 随机元素的 mul / inverse。
    for _ in 0..2 {
        let a = rng.next_cm31();
        let b = rng.next_cm31();
        println!(
            "example : {} * {} = {} := by decide",
            cm31_lean(a),
            cm31_lean(b),
            cm31_lean(a * b)
        );
        println!(
            "example : {} * {} = StwoLean.CM31.ofU32 1 0 := by decide",
            cm31_lean(a),
            cm31_lean(a.inverse())
        );
    }
    println!("end CM31");
    println!();
    println!("section QM31");

    // —— QM31：stwo 单元测试 test_ops 的全部断言 ——
    let qm0 = QM31::from_u32_unchecked(1, 2, 3, 4);
    let qm1 = QM31::from_u32_unchecked(4, 5, 6, 7);
    println!(
        "example : {} + {} = {} := by decide",
        qm31_lean(qm0),
        qm31_lean(qm1),
        qm31_lean(qm0 + qm1)
    );
    println!(
        "example : {} * {} = {} := by decide",
        qm31_lean(qm0),
        qm31_lean(qm1),
        qm31_lean(qm0 * qm1)
    );
    println!(
        "example : -{} = {} := by decide",
        qm31_lean(qm0),
        qm31_lean(-qm0)
    );
    println!(
        "example : {} - {} = {} := by decide",
        qm31_lean(qm0),
        qm31_lean(qm1),
        qm31_lean(qm0 - qm1)
    );
    // stwo test_inverse。
    println!(
        "example : {} * {} = StwoLean.QM31.ofU32 1 0 0 0 := by decide",
        qm31_lean(qm0),
        qm31_lean(qm0.inverse())
    );
    // 随机元素的 mul / inverse。
    for _ in 0..2 {
        let a = rng.next_qm31();
        let b = rng.next_qm31();
        println!(
            "example : {} * {} = {} := by decide",
            qm31_lean(a),
            qm31_lean(b),
            qm31_lean(a * b)
        );
        println!(
            "example : {} * {} = StwoLean.QM31.ofU32 1 0 0 0 := by decide",
            qm31_lean(a),
            qm31_lean(a.inverse())
        );
    }
    println!("end QM31");
    println!();
    println!("section Circle");

    // —— M31 圆群生成元的小标量倍点（与 stwo `repeated_double` 对拍）——
    for n in [1u32, 3, 7, 31] {
        let p = M31_CIRCLE_GEN.repeated_double(n);
        println!(
            "example : StwoLean.CirclePoint.repeatedDouble StwoLean.CirclePoint.m31Gen {} = {} := by decide",
            n,
            point_lean(p)
        );
    }
    // x 坐标倍增映射 vs. 整点倍加：double_x(p_n.x) 是 p_n 倍增一次
    // （repeated_double(n+1)）的 x 坐标，对应 stwo doctest
    // `double_x(p.x) == (p + p).x`。
    let p = M31_CIRCLE_GEN.repeated_double(3);
    let doubled = M31_CIRCLE_GEN.repeated_double(4);
    println!(
        "example : StwoLean.CirclePoint.doubleX ({}) = ({}) := by decide",
        m31_lean(p.x),
        m31_lean(doubled.x)
    );

    // —— 安全域圆群生成元的小标量倍点 ——
    let p = SECURE_FIELD_CIRCLE_GEN.repeated_double(2);
    println!(
        "example : StwoLean.CirclePoint.repeatedDouble StwoLean.CirclePoint.secureGen 2 = {} := by decide",
        point_secure_lean(p)
    );
    // 注：`getRandomPoint` 向量不在此对拍——其 Lean 表达式含 `⁻¹`
    // （ZMod 逆为 noncomputable choice），`decide` 无法内核归约；
    // 该算子由 `getRandomPoint_onCircle` 定理符号化验证。
    println!("end Circle");
    println!();
    println!("end StwoLean.Vectors");
}
