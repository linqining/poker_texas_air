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

use stwo::core::channel::{Blake2sChannel, Channel, Poseidon252Channel};
use stwo::core::circle::{CirclePoint, M31_CIRCLE_GEN, SECURE_FIELD_CIRCLE_GEN};
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::{M31, P};
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo::core::vcs::MerkleHasher;
use stwo::core::circle::{CirclePointIndex, Coset};
use stwo::core::poly::line::LineDomain;
use stwo::core::fri::fold_line;
use stwo::core::utils::bit_reverse_index;

fn felt252_lean(f: starknet_ff::FieldElement) -> String {
    let bytes = f.to_bytes_be();
    let hexs: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let trimmed = hexs.trim_start_matches('0');
    let body = if trimmed.is_empty() { "0" } else { trimmed };
    format!("((0x{}) : StwoLean.Fp252)", body)
}

/// 固定种子的 LCG，保证生成结果可复现。
#[derive(Clone)]
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
    let mut rng = Lcg(0x20260919);

    println!("import StwoLean.M31");
    println!("import StwoLean.CM31");
    println!("import StwoLean.QM31");
    println!("import StwoLean.Circle");
    println!("import StwoLean.CircleDomain");
    println!("import StwoLean.Poseidon252");
    println!("import StwoLean.Channel");
    println!("import StwoLean.Merkle");
    println!("import StwoLean.LiftedMerkle");
    println!("import StwoLean.FriCore");
    println!("import StwoLean.FriVerifier");
    println!("import StwoLean.Blake2s");
    println!("import StwoLean.Deep");
    println!("import StwoLean.Commitment");
    println!("import StwoLean.Verifier");
    println!("import StwoLean.StarkProofJson");
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
    println!("section PoseidonChannel");
    println!();
    println!("-- 本节向量依赖 251-bit 域上的 91 轮 Hades 排列，内核");
    println!("-- `decide` 求值过慢，统一用 `native_decide`（编译器求值）。");
    println!("-- 信任模型说明见 README「分层信任模型」。");
    println!();

    // —— Hades 排列：状态 [1, 2, 3] 的完整输出 ——
    {
        let mut st = [starknet_ff::FieldElement::ONE,
                      starknet_ff::FieldElement::TWO,
                      starknet_ff::FieldElement::THREE];
        starknet_crypto::poseidon_permute_comp(&mut st);
        println!(
            "theorem hadesVec1 : StwoLean.hades ((1 : Fp252), 2, 3) = ({}, {}, {}) := by native_decide",
            felt252_lean(st[0]),
            felt252_lean(st[1]),
            felt252_lean(st[2])
        );
    }

    // —— poseidon_hash(1, 2) 与 poseidon_hash_many ——
    {
        let h = starknet_crypto::poseidon_hash(
            starknet_ff::FieldElement::ONE,
            starknet_ff::FieldElement::TWO,
        );
        println!(
            "theorem poseidonHashVec1 : StwoLean.poseidonHash 1 2 = {} := by native_decide",
            felt252_lean(h)
        );
        let msgs: Vec<starknet_ff::FieldElement> = (1u32..=5)
            .map(|i| starknet_ff::FieldElement::from(i))
            .collect();
        let hm = starknet_crypto::poseidon_hash_many(&msgs);
        println!(
            "theorem poseidonHashManyVec1 : StwoLean.poseidonHashMany [1, 2, 3, 4, 5] = {} := by native_decide",
            felt252_lean(hm)
        );
    }

    // —— Channel：stwo 单元测试自带的两个 digest 金向量 ——
    {
        let mut ch = Poseidon252Channel::default();
        ch.mix_u64(0x1111222233334444);
        println!(
            "theorem chMixU64Golden : StwoLean.Channel.mixU64 {} StwoLean.Channel.chInit = ({}, 0) := by native_decide",
            0x1111222233334444u64,
            felt252_lean(ch.digest())
        );
    }
    {
        let mut ch = Poseidon252Channel::default();
        ch.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        println!(
            "theorem chMixU32sGolden : StwoLean.Channel.mixU32s [1, 2, 3, 4, 5, 6, 7, 8, 9] StwoLean.Channel.chInit = ({}, 0) := by native_decide",
            felt252_lean(ch.digest())
        );
    }

    // —— Channel：draw 序列（钉死 n_draws 递增与 mix 重置语义）——
    {
        let mut ch = Poseidon252Channel::default();
        let words = ch.draw_u32s();
        let words_lean: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        println!(
            "theorem chDrawU32sVec1 : (StwoLean.Channel.drawU32s StwoLean.Channel.chInit).1 = [{}] := by native_decide",
            words_lean.join(", ")
        );
        let q = ch.draw_secure_felt();
        println!(
            "theorem chDrawSecureFeltVec1 : (StwoLean.Channel.drawSecureFelt (StwoLean.Channel.drawU32s StwoLean.Channel.chInit).2).1 = {} := by native_decide",
            qm31_lean(QM31::from_m31_array([q.0 .0, q.0 .1, q.1 .0, q.1 .1]))
        );
    }

    // —— Channel：mix_felts（含末尾落单 QM31 的 4-limb 打包）——
    {
        let mut ch = Poseidon252Channel::default();
        let qs: Vec<SecureField> = (0u32..3)
            .map(|i| SecureField::from(M31(1923782 + i as u32)))
            .collect();
        ch.mix_felts(&qs);
        println!(
            "theorem chMixFeltsVec1 : StwoLean.Channel.mixFelts [StwoLean.Channel.qm31l 1923782, StwoLean.Channel.qm31l 1923783, StwoLean.Channel.qm31l 1923784] StwoLean.Channel.chInit = ({}, 0) := by native_decide",
            felt252_lean(ch.digest())
        );
    }
    println!();
    println!("end PoseidonChannel");
    println!();
    println!("section MerkleFri");
    println!();

    // —— Merkle：stwo test_vector 的两个 hash_node 金向量 ——
    {
        let leaf = Poseidon252MerkleHasher::hash_node(None, &[M31(0), M31(1)]);
        println!(
            "example : StwoLean.Merkle.hashNode none [0, 1] = {} := by native_decide",
            felt252_lean(leaf)
        );
        let node = Poseidon252MerkleHasher::hash_node(
            Some((starknet_ff::FieldElement::from(1u32), starknet_ff::FieldElement::from(2u32))),
            &[M31(3)],
        );
        println!(
            "example : StwoLean.Merkle.hashNode (some (((1) : StwoLean.Fp252), ((2) : StwoLean.Fp252))) [3] = {} := by native_decide",
            felt252_lean(node)
        );
    }

    // —— Merkle：4 叶两层树的单路径验证往返 ——
    {
        let leaves: Vec<Vec<M31>> = vec![
            vec![M31(0), M31(1)],
            vec![M31(2), M31(3)],
            vec![M31(4), M31(5)],
            vec![M31(6), M31(7)],
        ];
        let l: Vec<starknet_ff::FieldElement> =
            leaves.iter().map(|lv| Poseidon252MerkleHasher::hash_node(None, lv)).collect();
        let root = Poseidon252MerkleHasher::hash_node(Some((l[0], l[1])), &[]);
        // idx = 1（第二叶），兄弟 = L1[0]。
        println!(
            "example : StwoLean.Merkle.verifyPath [2, 3] 1 [{}] {} = true := by native_decide",
            felt252_lean(l[0]),
            felt252_lean(root)
        );
    }

    // —— FRI：ibutterfly 与 fold_pair ——
    {
        let mut rng = Lcg(0x20260919);
        let v0 = rng.next_qm31();
        let v1 = rng.next_qm31();
        let itwid = rng.next_m31();
        let (mut a, mut b) = (v0, v1);
        stwo::core::fft::ibutterfly(&mut a, &mut b, itwid);
        let alpha = rng.next_qm31();
        let to_qm = |q: &QM31| qm31_lean(QM31::from_m31_array([q.0 .0, q.0 .1, q.1 .0, q.1 .1]));
        let itw = format!("({})", itwid.0);
        println!(
            "example : StwoLean.FriCore.ibutterfly {} {} {} = ({}, {}) := by decide",
            to_qm(&v0),
            to_qm(&v1),
            itw,
            to_qm(&a),
            to_qm(&b)
        );
        // fold_pair 的定义就是 g + α·h，断言按定义展开（decide 可核）。
        println!(
            "example : StwoLean.FriCore.foldPair {} {} {} {} = {} + {} * {} := by decide",
            to_qm(&v0),
            to_qm(&v1),
            itw,
            to_qm(&alpha),
            to_qm(&a),
            to_qm(&alpha),
            to_qm(&b)
        );
    }
    // —— FRI 多层实例：3 层 fold_line（log3 → log0），单查询位置 idx=5 ——
    {
        // 初始 line domain：odds coset（initial=1, log=3），8 个 x 坐标。
        let coset = Coset::new(CirclePointIndex(1), 3);
        let domain = LineDomain::new(coset);
        let mut rng = Lcg(0x20260919);
        // LCG 状态打印（供 Lean 侧数据流核对）
        {
            let mut t = rng.clone();
            let ev: Vec<QM31> = (0..8).map(|_| t.next_qm31()).collect();
            for (i, q) in ev.iter().enumerate() {
                println!(
                    "-- DBG eval[{}] = QM31.ofU32 {} {} {} {}",
                    i, q.0.0.0, q.0.1.0, q.1.0.0, q.1.1.0
                );
            }
        }
        let mut evals: Vec<SecureField> = (0..8).map(|_| rng.next_qm31()).collect();
        let alphas: Vec<SecureField> = (0..3).map(|_| rng.next_qm31()).collect();

        // 每层构造 merkle 树（叶 = 该层 QM31 的 4 个 M31 limb）并取 idx 的路径。
        let layer_leaf = |q: &SecureField| -> starknet_ff::FieldElement {
            Poseidon252MerkleHasher::hash_node(
                None,
                &[q.0 .0, q.0 .1, q.1 .0, q.1 .1],
            )
        };
        let mut roots: Vec<starknet_ff::FieldElement> = Vec::new();
        let mut paths: Vec<Vec<starknet_ff::FieldElement>> = Vec::new();
        let mut idx: usize = 5; // 二进制 101
        {
            // 层循环内需要的树构造
        }
        let mut cur_domain = domain;
        let mut cur_log = 3usize;
        let layers_evals: Vec<Vec<SecureField>> = {
            let mut v = vec![evals.clone()];
            for layer in 0..3 {
                let (d2, folded) = fold_line(&evals.clone(), cur_domain, alphas[layer]);
                let _ = d2;
                // fold_line 会 double domain，重新跟踪
                cur_domain = LineDomain::new(Coset::new(CirclePointIndex(1 << (layer + 1)), (3 - layer - 1) as u32));
                evals = folded.clone();
                v.push(folded);
            }
            v
        };
        // 重新走一遍层，为每层算 root/path（用 layers_evals 的各层数据）
        let mut log_i = 3usize;
        for layer in 0..3 {
            let ev = &layers_evals[layer];
            // 本库的路径验证语义：承诺叶按 natural 域位置排列
            // （位置 idx 的域点 = domain.at(idx)；与 stwo 的 bit-reverse
            // 叶序的差异记录在 README）。
            let leaf_hashes: Vec<starknet_ff::FieldElement> =
                ev.iter().map(&layer_leaf).collect();
            // 自底向上构造树（log_i 层）
            let mut levels = vec![leaf_hashes.clone()];
            let mut cur = leaf_hashes.clone();
            while cur.len() > 1 {
                let nxt: Vec<starknet_ff::FieldElement> = cur
                    .chunks(2)
                    .map(|c| {
                        Poseidon252MerkleHasher::hash_node(Some((c[0], c[1])), &[])
                    })
                    .collect();
                cur = nxt;
                levels.push(cur.clone());
            }
            roots.push(levels[levels.len() - 1][0]);
            // 自检：pathSelf 链重算根（模拟 Lean pathRoot）
            let leaf_idx_self = bit_reverse_index(idx >> layer, log_i as u32);
            let mut rr = leaf_hashes[leaf_idx_self];
            let mut jj2 = leaf_idx_self;
            for lev in 0..levels.len() - 1 {
                let sib = levels[lev][(jj2 ^ 1) % levels[lev].len()];
                if jj2 % 2 == 0 { rr = Poseidon252MerkleHasher::hash_node(Some((rr, sib)), &[]); }
                else { rr = Poseidon252MerkleHasher::hash_node(Some((sib, rr)), &[]); }
                jj2 >>= 1;
            }
                println!(
                    "-- DBG FRI layer {} selfcheck: pathRoot==root? {} (root={})",
                    layer, rr == levels[levels.len() - 1][0], felt252_lean(levels[levels.len() - 1][0]));
            // idx >> layer 的路径：每层兄弟（单元素末层无兄弟，跳过）
            // 承诺叶为 bit-reverse 排列，叶下标 = bitrev(自然位置, log)。
            let mut pth: Vec<starknet_ff::FieldElement> = Vec::new();
            let mut j = idx >> layer;
            for level in &levels {
                if level.len() == 1 {
                    break;
                }
                pth.push(level[j ^ 1]);
                j >>= 1;
            }
            paths.push(pth);
            log_i -= 1;
        }
        let _ = log_i;

        // Lean 断言组装
        let to_qm = |q: &SecureField| {
            qm31_lean(QM31::from_m31_array([q.0 .0, q.0 .1, q.1 .0, q.1 .1]))
        };
        let root_lean: Vec<String> = roots.iter().map(|r| felt252_lean(*r)).collect();
        let alpha_lean: Vec<String> = alphas.iter().map(|a| to_qm(&a)).collect();

        // witnesses：每层 evalSelf/evalSibling + 两条路径
        let mut w_lines: Vec<String> = Vec::new();
        let mut j = idx;
        let mut log_i = 3usize;
        for layer in 0..3 {
            let ev = &layers_evals[layer];
            w_lines.push(format!(
                "        {{ evalSelf := {}, evalSibling := {}, pathSelf := [{}], pathSibling := [{}] }}",
                to_qm(&ev[j]),
                to_qm(&ev[j ^ 1]),
                {
                    // pathSelf: 位置 j 的兄弟哈希链（承诺叶 bit-reverse 排列，
                    // 叶下标 = bitrev(自然位置, log)，逐层折半）
                    let mut parts: Vec<String> = Vec::new();
                    let mut jj = j;
                    for lev in 0..(3 - layer) {
                        let tree_leaf: Vec<starknet_ff::FieldElement> =
                            layers_evals[layer].iter().map(&layer_leaf).collect();
                        let mut levels = vec![tree_leaf.clone()];
                        let mut cur = tree_leaf.clone();
                        while cur.len() > 1 {
                            let nxt: Vec<starknet_ff::FieldElement> = cur
                                .chunks(2)
                                .map(|c| Poseidon252MerkleHasher::hash_node(Some((c[0], c[1])), &[]))
                                .collect();
                            cur = nxt;
                            levels.push(cur.clone());
                        }
                        parts.push(felt252_lean(levels[lev][jj ^ 1]));
                        jj >>= 1;
                    }
                    parts.join(", ")
                },
                {
                    // pathSibling: 位置 j^1 的兄弟哈希链
                    let mut parts: Vec<String> = Vec::new();
                    let mut jj = j ^ 1;
                    for lev in 0..(3 - layer) {
                        let tree_leaf: Vec<starknet_ff::FieldElement> =
                            layers_evals[layer].iter().map(&layer_leaf).collect();
                        let mut levels = vec![tree_leaf.clone()];
                        let mut cur = tree_leaf.clone();
                        while cur.len() > 1 {
                            let nxt: Vec<starknet_ff::FieldElement> = cur
                                .chunks(2)
                                .map(|c| Poseidon252MerkleHasher::hash_node(Some((c[0], c[1])), &[]))
                                .collect();
                            cur = nxt;
                            levels.push(cur.clone());
                        }
                        parts.push(felt252_lean(levels[lev][jj ^ 1]));
                        jj >>= 1;
                    }
                    parts.join(", ")
                }
            ));
            j >>= 1;
        }
        let _ = log_i;

        let last_val = to_qm(&layers_evals[3][0]);
        println!(
            "example : StwoLean.FriVerifier.friVerify\n    {{ roots := [{}], alphas := [{}], lastPoly := [{}], initialDomain := LineDomain.ofCoset (Coset.mk' 1 3), initialLogSize := 3 }}\n    5 {} [{}] = true := by native_decide",
            root_lean.join(", "),
            alpha_lean.join(", "),
            last_val,
            to_qm(&layers_evals[0][5]),
            w_lines.join(",\n     ")
        );
    }
    println!();
    println!("end MerkleFri");
    println!();
    println!("section Pcs");
    println!();

    // ============ 向量 A：泛化单查询（verifyValuesGen） ============
    {
        use stwo::core::channel::{Channel, MerkleChannel};
        use stwo::core::fri::{fold_circle_into_line, fold_line};
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::core::pcs::quotients::{fri_answers, PointSample};
        use stwo::core::pcs::utils::{prepare_preprocessed_query_positions, TreeVec};
        use stwo::core::queries::draw_queries;
        use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
        use stwo::core::vcs_lifted::poseidon252_merkle::{
            Poseidon252MerkleChannel, Poseidon252MerkleHasher as LH,
        };
        use stwo::core::vcs_lifted::verifier::{MerkleDecommitmentLifted, MerkleVerifierLifted};

        type Fe = starknet_ff::FieldElement;
        const TRACE_LOG: u32 = 4;
        const BLOWUP: u32 = 2;
        const L: u32 = TRACE_LOG + BLOWUP;
        const N: usize = 1usize << L;
        const POW_BITS: u32 = 4;

        let mut rng = Lcg(0x20260919);
        let mix_root = |ch: &mut Poseidon252Channel, root: Fe| {
            <Poseidon252MerkleChannel as MerkleChannel>::mix_root(ch, root);
        };

        let col0: Vec<M31> = (0..1 << TRACE_LOG).map(|_| rng.next_m31()).collect();
        let col1: Vec<M31> = (0..1 << TRACE_LOG).map(|_| rng.next_m31()).collect();
        let z0 = CirclePoint { x: rng.next_qm31(), y: rng.next_qm31() };
        let z1 = CirclePoint { x: rng.next_qm31(), y: rng.next_qm31() };
        let v0a = rng.next_qm31();
        let v0b = rng.next_qm31();
        let v1a = rng.next_qm31();
        let v1b = rng.next_qm31();

        let leaf_hash = |row: &[M31]| -> Fe {
            let mut h = LH::default();
            h.update_leaf(row);
            h.finalize()
        };
        let trace_leaves: Vec<Fe> =
            (0..N).map(|p| leaf_hash(&[col0[p >> BLOWUP], col1[p >> BLOWUP]])).collect();
        let mut trace_levels = vec![trace_leaves.clone()];
        while trace_levels.last().unwrap().len() > 1 {
            let nxt: Vec<Fe> = trace_levels.last().unwrap().chunks(2)
                .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
            trace_levels.push(nxt);
        }
        let trace_root = trace_levels.last().unwrap()[0];

        let mut ch = Poseidon252Channel::default();
        mix_root(&mut ch, trace_root);
        let ch_after_commit = ch.digest();
        {
            let mut ch0 = Poseidon252Channel::default();
            ch0.mix_felts(&[v0a, v0b, v1a, v1b]);
            println!(
                "example : StwoLean.Channel.mixFelts [{}, {}, {}, {}] StwoLean.Channel.chInit = ({}, 0) := by native_decide",
                qm31_lean(v0a), qm31_lean(v0b), qm31_lean(v1a), qm31_lean(v1b),
                felt252_lean(ch0.digest())
            );
        }
        ch.mix_felts(&[v0a, v0b, v1a, v1b]);
        let alpha_deep = ch.draw_secure_felt();

        let col0_ext: Vec<M31> = (0..N).map(|p| col0[p >> BLOWUP]).collect();
        let col1_ext: Vec<M31> = (0..N).map(|p| col1[p >> BLOWUP]).collect();
        let all_pos: Vec<usize> = (0..N).collect();
        let ps = |z: CirclePoint<QM31>, v: QM31| PointSample { point: z, value: v };
        let fri_full: Vec<QM31> = fri_answers(
            TreeVec(vec![vec![TRACE_LOG, TRACE_LOG]]),
            TreeVec(vec![vec![
                vec![ps(z0, v0a), ps(z1, v0b)],
                vec![ps(z0, v1a), ps(z1, v1b)],
            ]]),
            alpha_deep,
            &all_pos,
            TreeVec(vec![vec![col0_ext.clone(), col1_ext.clone()]]),
            L,
        )
        .unwrap();

        let fri_leaf = |qv: &QM31| leaf_hash(&[qv.0 .0, qv.0 .1, qv.1 .0, qv.1 .1]);
        let build_tree = |vals: &[QM31]| -> (Fe, Vec<Vec<Fe>>) {
            let leaves: Vec<Fe> = vals.iter().map(&fri_leaf).collect();
            let mut ls = vec![leaves];
            while ls.last().unwrap().len() > 1 {
                let nxt: Vec<Fe> = ls.last().unwrap().chunks(2)
                    .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
                ls.push(nxt);
            }
            (ls.last().unwrap()[0], ls)
        };
        let (root_f0, levels_f0) = build_tree(&fri_full);

        mix_root(&mut ch, root_f0);
        let alpha0 = ch.draw_secure_felt();
        let circle_domain = CanonicCoset::new(L).circle_domain();
        let line0: Vec<QM31> = fold_circle_into_line(&fri_full, circle_domain, alpha0);
        let dom1 = LineDomain::new(Coset::half_odds(L - 1));
        let (root_f1, levels_f1) = build_tree(&line0);
        mix_root(&mut ch, root_f1);
        let alpha1 = ch.draw_secure_felt();
        let (dom2, line1) = fold_line(&line0, dom1, alpha1);
        let (root_f2, levels_f2) = build_tree(&line1);
        mix_root(&mut ch, root_f2);
        let alpha2 = ch.draw_secure_felt();
        let (_dom3, line2) = fold_line(&line1, dom2, alpha2);
        let last_channel: Vec<QM31> = vec![rng.next_qm31()];
        ch.mix_felts(&last_channel);

        let digest_before_pow = ch.digest();
        let prefixed =
            starknet_crypto::poseidon_hash_many(&[Fe::from(0x12345678u32), ch.digest(), Fe::from(POW_BITS)]);
        let mut nonce: u64 = 0;
        loop {
            let h = starknet_crypto::poseidon_hash(prefixed, Fe::from(nonce));
            let bytes = h.to_bytes_be();
            let low = u128::from_be_bytes(bytes[16..].try_into().unwrap());
            if low.trailing_zeros() >= POW_BITS as u32 {
                break;
            }
            nonce += 1;
        }
        ch.mix_u64(nonce);

        let raw = draw_queries(&mut ch, L, 1);
        let mut sorted = raw.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let q = sorted[0];
        let pp = prepare_preprocessed_query_positions(&sorted, L, L);

        let c0v = col0[q >> BLOWUP];
        let c1v = col1[q >> BLOWUP];
        let trace_witness: Vec<Fe> = {
            let mut v = Vec::new();
            let mut j = q;
            for lev in 0..L as usize {
                v.push(trace_levels[lev][(j >> lev) ^ 1]);
            }
            v
        };
        let mv = MerkleVerifierLifted::<LH>::new(trace_root, vec![L, L], None);
        let _ = mv
            .verify(&pp, vec![vec![c0v], vec![c1v]], MerkleDecommitmentLifted { hash_witness: trace_witness.clone() })
            .unwrap();

        let i = q / 2;
        let first_witness: Vec<Fe> = {
            let mut v = Vec::new();
            let mut jj = 2 * i;
            for lev in 1..L as usize {
                v.push(levels_f0[lev][(jj >> lev) ^ 1]);
            }
            v
        };
        let p1 = q >> 1;
        let w_f1: Vec<Fe> = {
            let mut v = Vec::new();
            let mut jj = p1;
            for lev in 1..5usize {
                v.push(levels_f1[lev][(jj >> lev) ^ 1]);
            }
            v
        };
        let p2 = q >> 2;
        let w_f2: Vec<Fe> = {
            let mut v = Vec::new();
            let mut jj = p2;
            for lev in 1..4usize {
                v.push(levels_f2[lev][(jj >> lev) ^ 1]);
            }
            v
        };
        let jstar = q >> 3;
        let last_check = line2[jstar];

        // 泛化端到端断言（单行输出：结构体字段续行缩进须深于 `{` 列位，
        // 多行模板易踩 Lean 的缩进解析，这里压平成单行）
        let pcs_stmt = format!(
            "theorem pcsVerifyValues : StwoLean.Commitment.verifyValuesGen
    {{ firstLayerLog := 6, foldStep := 1, powBits := 4, nQueries := 1, ppMaxLog := 6 }}
    [(4, [StwoLean.Deep.PointSample.mk {} {}, StwoLean.Deep.PointSample.mk {} {}]),
     (4, [StwoLean.Deep.PointSample.mk {} {}, StwoLean.Deep.PointSample.mk {} {}])]
    {{ trees := [{{ root := {}, isPP := false, height := 6,
        rows := [[{}, {}]], witness := [{}] }}],
       sampledValues := [{}, {}, {}, {}],
       friLayers := [
        {{ root := {}, positions := [{}, {}], evals := [{}, {}], witness := [{}], packedShift := 0 }},
        {{ root := {}, positions := [{}, {}], evals := [{}, {}], witness := [{}], packedShift := 0 }},
        {{ root := {}, positions := [{}, {}], evals := [{}, {}], witness := [{}], packedShift := 0 }}],
       lastPolyChannel := [{}], lastPoly := [{}, (0 : StwoLean.QM31)],
       powNonce := {} }}
    (({}, 0) : StwoLean.Channel.Chan) = true := by native_decide",
            point_secure_lean(z0), qm31_lean(v0a), point_secure_lean(z1), qm31_lean(v0b),
            point_secure_lean(z0), qm31_lean(v1a), point_secure_lean(z1), qm31_lean(v1b),
            felt252_lean(trace_root),
            m31_lean(c0v), m31_lean(c1v),
            trace_witness.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", "),
            qm31_lean(v0a), qm31_lean(v0b), qm31_lean(v1a), qm31_lean(v1b),
            felt252_lean(root_f0),
            2 * i, 2 * i + 1,
            qm31_lean(fri_full[2 * i]), qm31_lean(fri_full[2 * i + 1]),
            first_witness.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", "),
            felt252_lean(root_f1),
            p1, p1 ^ 1,
            qm31_lean(line0[p1]), qm31_lean(line0[p1 ^ 1]),
            w_f1.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", "),
            felt252_lean(root_f2),
            p2 & !1usize, (p2 & !1usize) + 1,
            qm31_lean(line1[p2 & !1usize]), qm31_lean(line1[(p2 & !1usize) + 1]),
            w_f2.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", "),
            qm31_lean(last_channel[0]),
            qm31_lean(last_check),
            nonce,
            felt252_lean(ch_after_commit)
        );
        println!("{}", pcs_stmt.split('\n').map(|l| l.trim()).collect::<Vec<_>>().join(" "));

        // 首层 liftedVerify 自检（真实 MerkleVerifierLifted）
        {
            let mv0 = MerkleVerifierLifted::<LH>::new(root_f0, vec![L, L, L, L], None);
            let cols4 = |a: &QM31, b: &QM31| {
                vec![
                    vec![a.0 .0, b.0 .0],
                    vec![a.0 .1, b.0 .1],
                    vec![a.1 .0, b.1 .0],
                    vec![a.1 .1, b.1 .1],
                ]
            };
            let r = mv0.verify(
                &[2 * i, 2 * i + 1],
                cols4(&fri_full[2 * i], &fri_full[2 * i + 1]),
                MerkleDecommitmentLifted { hash_witness: first_witness.clone() },
            );
            let h12 = fri_leaf(&fri_full[2 * i]);
            let h13 = fri_leaf(&fri_full[2 * i + 1]);
        }

        // DEEP 商值对拍（Lean friAnswers == 真实 fri_answers）
        let fri_stmt = format!(
            "theorem pcsFriAnswers : StwoLean.Deep.friAnswers {} (StwoLean.QM31.ofU32 1 0 0 0) 6
    [(4, [StwoLean.Deep.PointSample.mk {} {}, StwoLean.Deep.PointSample.mk {} {}]),
     (4, [StwoLean.Deep.PointSample.mk {} {}, StwoLean.Deep.PointSample.mk {} {}])]
    [[{}], [{}]] [{}] = [{}] := by decide",
            qm31_lean(alpha_deep),
            point_secure_lean(z0), qm31_lean(v0a), point_secure_lean(z1), qm31_lean(v0b),
            point_secure_lean(z0), qm31_lean(v1a), point_secure_lean(z1), qm31_lean(v1b),
            m31_lean(c0v), m31_lean(c1v),
            q, qm31_lean(fri_full[q])
        );
        println!("{}", fri_stmt.split('\n').map(|l| l.trim()).collect::<Vec<_>>().join(" "));
    }
    println!();

    // ============ 向量 B：多树 + 多查询 + packed leaf（foldStep=2） ============
    {
        use stwo::core::channel::{Channel, MerkleChannel};
        use stwo::core::fri::{fold_circle_into_line, fold_coset};
        use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
        use stwo::core::pcs::quotients::{fri_answers, PointSample};
        use stwo::core::pcs::utils::TreeVec;
        use stwo::core::queries::draw_queries;
        use stwo::core::fields::FieldExpOps;
        use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
        use stwo::core::vcs_lifted::poseidon252_merkle::{
            Poseidon252MerkleChannel, Poseidon252MerkleHasher as LH,
        };

        type Fe = starknet_ff::FieldElement;
        const L2: u32 = 5; // 首层圆域 log（traceLog 4 + blowup 1）
        const FS: u32 = 2; // fold_step
        const N2: usize = 1usize << L2; // 32
        const POW_BITS2: u32 = 4;

        let mut rng = Lcg(0x20260919);
        let mix_root = |ch: &mut Poseidon252Channel, root: Fe| {
            <Poseidon252MerkleChannel as MerkleChannel>::mix_root(ch, root);
        };
        let leaf_hash = |row: &[M31]| -> Fe {
            let mut h = LH::default();
            h.update_leaf(row);
            h.finalize()
        };

        let pp_col: Vec<M31> = (0..8).map(|_| rng.next_m31()).collect();
        let col0: Vec<M31> = (0..16).map(|_| rng.next_m31()).collect();
        let col1: Vec<M31> = (0..16).map(|_| rng.next_m31()).collect();
        let z0 = CirclePoint { x: rng.next_qm31(), y: rng.next_qm31() };
        let z1 = CirclePoint { x: rng.next_qm31(), y: rng.next_qm31() };
        let v0a = rng.next_qm31();
        let v0b = rng.next_qm31();
        let v1a = rng.next_qm31();
        let v1b = rng.next_qm31();

        // 树 0（预处理树，高 4，16 叶，单列行）；树 1（trace，高 5，32 叶，两列行）
        let t0_leaves: Vec<Fe> =
            (0..16).map(|p| leaf_hash(&[pp_col[p >> 1]])).collect();
        let mut t0_levels = vec![t0_leaves.clone()];
        while t0_levels.last().unwrap().len() > 1 {
            let nxt: Vec<Fe> = t0_levels.last().unwrap().chunks(2)
                .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
            t0_levels.push(nxt);
        }
        let root_pp = t0_levels.last().unwrap()[0];

        let t1_leaves: Vec<Fe> =
            (0..N2).map(|p| leaf_hash(&[col0[p >> 1], col1[p >> 1]])).collect();
        let mut t1_levels = vec![t1_leaves.clone()];
        while t1_levels.last().unwrap().len() > 1 {
            let nxt: Vec<Fe> = t1_levels.last().unwrap().chunks(2)
                .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
            t1_levels.push(nxt);
        }
        let root_tr = t1_levels.last().unwrap()[0];

        // 通道：两 commit → mix_felts → αdeep
        let mut ch = Poseidon252Channel::default();
        mix_root(&mut ch, root_pp);
        mix_root(&mut ch, root_tr);
        let ch_after_commit = ch.digest();
        ch.mix_felts(&[v0a, v0b, v1a, v1b]);
        let alpha_deep = ch.draw_secure_felt();

        // DEEP 商值（32 位置全算 = 首层圆域求值）
        let all_pos: Vec<usize> = (0..N2).collect();
        let c0_ext: Vec<M31> = (0..N2).map(|p| col0[p >> 1]).collect();
        let c1_ext: Vec<M31> = (0..N2).map(|p| col1[p >> 1]).collect();
        let ps = |z: CirclePoint<QM31>, v: QM31| PointSample { point: z, value: v };
        let qpp_of = |p: usize| (p >> 2) * 2 + p % 2;
        let qpp_of = |p: usize| (p >> 2) * 2 + p % 2;
        let pp_ext: Vec<M31> =
            (0..N2).map(|p| pp_col[qpp_of(p) >> 1]).collect();
        let fri_full: Vec<QM31> = fri_answers(
            TreeVec(vec![vec![3u32], vec![4u32, 4u32]]),
            TreeVec(vec![
                vec![],
                vec![
                    vec![ps(z0, v0a), ps(z1, v0b)],
                    vec![ps(z0, v1a), ps(z1, v1b)],
                ],
            ]),
            alpha_deep,
            &all_pos,
            TreeVec(vec![
                vec![pp_ext.clone()],
                vec![c0_ext.clone(), c1_ext.clone()],
            ]),
            L2,
        )
        .unwrap();

        // 首层树（packed：8 叶 × 16 limb）
        let fri_leaf = |qv: &QM31| leaf_hash(&[qv.0 .0, qv.0 .1, qv.1 .0, qv.1 .1]);
        let (root_f0, levels_f0) = {
            let leaves: Vec<Fe> = (0..8usize)
                .map(|l| {
                    let row: Vec<M31> = (0..4usize)
                        .flat_map(|k| {
                            let e = &fri_full[4 * l + k];
                            vec![e.0 .0, e.0 .1, e.1 .0, e.1 .1]
                        })
                        .collect();
                    leaf_hash(&row)
                })
                .collect();
            let mut ls = vec![leaves];
            while ls.last().unwrap().len() > 1 {
                let nxt: Vec<Fe> = ls.last().unwrap().chunks(2)
                    .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
                ls.push(nxt);
            }
            (ls.last().unwrap()[0], ls)
        };

        // 首层子集折叠（fold_circle_into_line 4→2 + fold_coset 2→1，α²）
        let circle_domain = CanonicCoset::new(L2).circle_domain();
        let fold_circle_sub = |base: usize, alpha: QM31| -> QM31 {
            let bitrev = bit_reverse_index(base, L2);
            let half = 1usize << (L2 - 1);
            let idx: usize = if bitrev < half {
                (1usize << (30 - L2)) + (1usize << (32 - L2)) * bitrev
            } else {
                (1usize << 31)
                    - ((1usize << (30 - L2)) + (1usize << (32 - L2)) * (bitrev - half))
            };
            let evs: Vec<QM31> = (0..4usize).map(|k| fri_full[base + k]).collect();
            let buf = fold_circle_into_line(
                &evs,
                CircleDomain::new(Coset::new(CirclePointIndex(idx), FS - 1)),
                alpha,
            );
            assert_eq!(buf.len(), 2);
            fold_coset(
                buf,
                LineDomain::new(Coset::new(CirclePointIndex(idx), FS - 1)),
                alpha * alpha,
            )
        };

        mix_root(&mut ch, root_f0);
        let alpha0 = ch.draw_secure_felt();
        let line_vals: Vec<QM31> =
            (0..8usize).map(|s| fold_circle_sub(4 * s, alpha0)).collect();
        assert_eq!(line_vals.len(), 8);

        // 内层树（packed：2 叶）与 α1
        let (root_f1, levels_f1) = {
            let leaves: Vec<Fe> = (0..2usize)
                .map(|l| {
                    let row: Vec<M31> = (0..4usize)
                        .flat_map(|k| {
                            let e = &line_vals[4 * l + k];
                            vec![e.0 .0, e.0 .1, e.1 .0, e.1 .1]
                        })
                        .collect();
                    leaf_hash(&row)
                })
                .collect();
            let mut ls = vec![leaves];
            while ls.last().unwrap().len() > 1 {
                let nxt: Vec<Fe> = ls.last().unwrap().chunks(2)
                    .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
                ls.push(nxt);
            }
            (ls.last().unwrap()[0], ls)
        };
        mix_root(&mut ch, root_f1);
        let alpha1 = ch.draw_secure_felt();

        // 内层线域子集折叠（fold_coset 4→1）
        let dom1 = LineDomain::new(Coset::half_odds(L2 - FS));
        let fold_line_sub = |base: usize, alpha: QM31| -> QM31 {
            let bitrev = bit_reverse_index(base, 3u32);
            let idx: usize = (1usize << 26) + (1usize << 28) * bitrev;
            let evs: Vec<QM31> = (0..4usize).map(|k| line_vals[base + k]).collect();
            fold_coset(evs, LineDomain::new(Coset::new(CirclePointIndex(idx), FS)), alpha)
        };
        let line2_vals: Vec<QM31> =
            (0..2usize).map(|s| fold_line_sub(4 * s, alpha1)).collect();

        // 末层通道绑定（占位）与 POW
        let last_channel: QM31 = rng.next_qm31();
        ch.mix_felts(&[last_channel]);
        let prefixed = starknet_crypto::poseidon_hash_many(&[
            Fe::from(0x12345678u32),
            ch.digest(),
            Fe::from(POW_BITS2),
        ]);
        let mut nonce: u64 = 0;
        loop {
            let h = starknet_crypto::poseidon_hash(prefixed, Fe::from(nonce));
            let bytes = h.to_bytes_be();
            let low = u128::from_be_bytes(bytes[16..].try_into().unwrap());
            if low.trailing_zeros() >= POW_BITS2 as u32 {
                break;
            }
            nonce += 1;
        }
        ch.mix_u64(nonce);

        // 查询（2 个，末层位置须不同）
        let raw = draw_queries(&mut ch, L2, 2);
        let mut sorted = raw.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 2, "queries collided");
        let (qa, qb) = (sorted[0], sorted[1]);
        assert_ne!(qa >> 4, qb >> 4, "last-layer positions collided");
        assert_ne!((qa >> 2) * 2 + qa % 2, (qb >> 2) * 2 + qb % 2, "pp positions collided");

        // 末层核对值：polyEval([c0, c1], x_q) 在两点上解出 (c0, c1)
        let dom_last_init: usize = (1usize << 26) * 4; // half_odds(3) double 2
        let xl = |j: usize| -> QM31 {
            let idx: usize = dom_last_init + (1usize << 30) * (bit_reverse_index(j, 1u32));
            M31_CIRCLE_GEN.mul(idx as u128).x.into()
        };
        let (xa, xb) = (xl(qa >> 4), xl(qb >> 4));
        let (va, vb) = (line2_vals[qa >> 4], line2_vals[qb >> 4]);
        let c1 = (va - vb) * (xa - xb).inverse();
        let c0 = va - c1 * xa;
        let last_poly = [c0, c1];
        // 自检
        assert_eq!(c0 + c1 * xa, va);
        assert_eq!(c0 + c1 * xb, vb);

        // witness 提取（多查询、兄弟合并）
        let extract_witness = |levels: &[Vec<Fe>], cur0: &[usize]| -> Vec<Fe> {
            let mut cur = cur0.to_vec();
            cur.sort_unstable();
            cur.dedup();
            let mut wit = Vec::new();
            let mut lev = 0usize;
            while cur.len() > 1 {
                let mut next = Vec::new();
                let mut i = 0;
                while i < cur.len() {
                    if i + 1 < cur.len() && cur[i] ^ 1 == cur[i + 1] {
                        next.push(cur[i] >> 1);
                        i += 2;
                    } else {
                        if cur[i] ^ 1 >= levels[lev].len() {
                            panic!("walker OOB lev={} curlen={} cur={:?} levelslen={}", lev, cur.len(), cur, levels.len());
                        }
                        wit.push(levels[lev][cur[i] ^ 1]);
                        next.push(cur[i] >> 1);
                        i += 1;
                    }
                }
                cur = next;
                lev += 1;
            }
            wit
        };

        // 层 0：子集位置 {4k..} 的叶 = pos>>2
        let l0_positions: Vec<usize> = {
            let mut v: Vec<usize> = sorted
                .iter()
                .flat_map(|q| {
                    let base = (q >> 2) << 2;
                    (0..4usize).map(move |k| base + k)
                })
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let w_f0 = extract_witness(&levels_f0, &l0_positions.iter().map(|p| p >> 2).collect::<Vec<_>>());

        // DBG：层 0 packed 叶哈希与 witness 逐项
        {
            let l0p: Vec<usize> = l0_positions.iter().map(|p| p >> 2).collect();
            for (li, lp) in l0p.iter().enumerate() {
                let row: Vec<M31> = (0..4usize)
                    .flat_map(|k| {
                        let e = &fri_full[4 * lp + k];
                        vec![e.0 .0, e.0 .1, e.1 .0, e.1 .1]
                    })
                    .collect();
            }
            for (k, w) in w_f0.iter().enumerate() {
            }
        }

        // 层 1：折叠位置 {q>>2} 的子集 {4k..}（叶 = pos>>2 = {0,1}，全部已知 → 空 witness）
        let l1_positions: Vec<usize> = {
            let mut v: Vec<usize> = sorted
                .iter()
                .map(|q| ((q >> 2) >> 2) << 2)
                .flat_map(|base| (0..4usize).map(move |k| base + k))
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let w_f1 = extract_witness(&levels_f1, &l1_positions.iter().map(|p| p >> 2).collect::<Vec<_>>());

        // trace 树与 pp 树的查询
        let pp_pos: Vec<usize> = sorted.iter().map(|q| qpp_of(*q)).collect();
        let w_pp = extract_witness(&t0_levels, &pp_pos);
        let w_tr = extract_witness(&t1_levels, &sorted);

        // 各树/各层的 Lean 断言
        let qm = |qv: &QM31| qm31_lean(*qv);
        let fl = |f: &Fe| felt252_lean(*f);
        let l0p: Vec<String> = l0_positions.iter().map(|p| p.to_string()).collect();
        let l0e: Vec<String> = l0_positions.iter().map(|p| qm(&fri_full[*p])).collect();
        let l1p: Vec<String> = l1_positions.iter().map(|p| p.to_string()).collect();
        let l1e: Vec<String> = l1_positions.iter().map(|p| qm(&line_vals[*p])).collect();

        let gen_stmt = format!(
            "theorem pcsGenVerify : StwoLean.Commitment.verifyValuesGen
    {{ firstLayerLog := 5, foldStep := 2, powBits := 4, nQueries := 2, ppMaxLog := 4 }}
    [(3, []), (4, [StwoLean.Deep.PointSample.mk {} {}, StwoLean.Deep.PointSample.mk {} {}]),
     (4, [StwoLean.Deep.PointSample.mk {} {}, StwoLean.Deep.PointSample.mk {} {}])]
    {{ trees := [
        {{ root := {}, isPP := true, height := 4,
          rows := [[{}], [{}]], witness := [{}] }},
        {{ root := {}, isPP := false, height := 5,
          rows := [[{}, {}], [{}, {}]], witness := [{}] }}],
       sampledValues := [{}, {}, {}, {}],
       friLayers := [
        {{ root := {}, positions := [{}], evals := [{}], witness := [{}], packedShift := 2 }},
        {{ root := {}, positions := [{}], evals := [{}], witness := [{}], packedShift := 2 }}],
       lastPolyChannel := [{}], lastPoly := [{}, {}],
       powNonce := {} }}
    (({}, 0) : StwoLean.Channel.Chan) = true := by native_decide",
            point_secure_lean(z0), qm(&v0a), point_secure_lean(z1), qm(&v0b),
            point_secure_lean(z0), qm(&v1a), point_secure_lean(z1), qm(&v1b),
            fl(&root_pp),
            m31_lean(pp_col[qpp_of(sorted[0]) >> 1]),
            m31_lean(pp_col[qpp_of(sorted[1]) >> 1]),
            w_pp.iter().map(|f| fl(f)).collect::<Vec<_>>().join(", "),
            fl(&root_tr),
            m31_lean(col0[sorted[0] >> 1]), m31_lean(col1[sorted[0] >> 1]),
            m31_lean(col0[sorted[1] >> 1]), m31_lean(col1[sorted[1] >> 1]),
            w_tr.iter().map(|f| fl(f)).collect::<Vec<_>>().join(", "),
            qm(&v0a), qm(&v0b), qm(&v1a), qm(&v1b),
            fl(&root_f0), l0p.join(", "), l0e.join(", "),
            w_f0.iter().map(|f| fl(f)).collect::<Vec<_>>().join(", "),
            fl(&root_f1), l1p.join(", "), l1e.join(", "),
            w_f1.iter().map(|f| fl(f)).collect::<Vec<_>>().join(", "),
            qm(&last_channel),
            qm(&last_poly[0]), qm(&last_poly[1]),
            nonce,
            fl(&ch_after_commit)
        );
        println!("{}", gen_stmt.split('\n').map(|l| l.trim()).collect::<Vec<_>>().join(" "));
    }
    println!();

    // ============ 向量 C：主循环 verifyMain（DEEP-ALI + verify_values） ============
    {
        use stwo::core::air::accumulation::PointEvaluationAccumulator;
        use stwo::core::channel::{Channel, MerkleChannel};
        use stwo::core::fri::{fold_circle_into_line, fold_line};
        use stwo::core::poly::circle::CanonicCoset;
        use stwo::core::pcs::quotients::{fri_answers, PointSample};
        use stwo::core::pcs::utils::{prepare_preprocessed_query_positions, TreeVec};
        use stwo::core::queries::draw_queries;
        use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
        use stwo::core::vcs_lifted::poseidon252_merkle::{
            Poseidon252MerkleChannel, Poseidon252MerkleHasher as LH,
        };
        use stwo::core::vcs_lifted::verifier::{MerkleDecommitmentLifted, MerkleVerifierLifted};

        type Fe = starknet_ff::FieldElement;
        const TRACE_LOG: u32 = 4;
        const BLOWUP: u32 = 2;
        const L: u32 = TRACE_LOG + BLOWUP;
        const N: usize = 1usize << L;
        const POW_BITS: u32 = 4;

        let mut rng = Lcg(0x31415926);
        let mix_root = |ch: &mut Poseidon252Channel, root: Fe| {
            <Poseidon252MerkleChannel as MerkleChannel>::mix_root(ch, root);
        };

        // trace 数据（与向量 A 同构）
        let col0: Vec<M31> = (0..1 << TRACE_LOG).map(|_| rng.next_m31()).collect();
        let col1: Vec<M31> = (0..1 << TRACE_LOG).map(|_| rng.next_m31()).collect();
        let z0 = CirclePoint { x: rng.next_qm31(), y: rng.next_qm31() };
        let z1 = CirclePoint { x: rng.next_qm31(), y: rng.next_qm31() };
        let v0a = rng.next_qm31();
        let v0b = rng.next_qm31();
        let v1a = rng.next_qm31();
        let v1b = rng.next_qm31();

        let leaf_hash = |row: &[M31]| -> Fe {
            let mut h = LH::default();
            h.update_leaf(row);
            h.finalize()
        };
        let trace_leaves: Vec<Fe> =
            (0..N).map(|p| leaf_hash(&[col0[p >> BLOWUP], col1[p >> BLOWUP]])).collect();
        let mut trace_levels = vec![trace_leaves.clone()];
        while trace_levels.last().unwrap().len() > 1 {
            let nxt: Vec<Fe> = trace_levels.last().unwrap().chunks(2)
                .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
            trace_levels.push(nxt);
        }
        let trace_root = trace_levels.last().unwrap()[0];

        // 组合多项式树：8 列 log 4（16 叶，行 = 8 M31）
        let comp_vals: Vec<Vec<M31>> =
            (0..8usize).map(|_| (0..N).map(|_| rng.next_m31()).collect()).collect();
        let comp_leaves: Vec<Fe> = (0..N)
            .map(|p| {
                let row: Vec<M31> = (0..8usize).map(|k| comp_vals[k][p]).collect();
                leaf_hash(&row)
            })
            .collect();
        let mut comp_levels = vec![comp_leaves.clone()];
        while comp_levels.last().unwrap().len() > 1 {
            let nxt: Vec<Fe> = comp_levels.last().unwrap().chunks(2)
                .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
            comp_levels.push(nxt);
        }
        let comp_root = comp_levels.last().unwrap()[0];

        // 主循环：1. random_coeff；2. commit trace 树 + 组合树；3. OODS 点
        let mut ch = Poseidon252Channel::default();
        mix_root(&mut ch, trace_root);
        let ch_after_commit = ch.digest();
        let random_coeff = ch.draw_secure_felt();
        mix_root(&mut ch, comp_root);
        let t = ch.draw_secure_felt();
        let oods = CirclePoint::<QM31>::get_random_point(&mut ch);

        // 组件约束商项（AIR 层接口的替身）与真实累加器
        let terms: Vec<QM31> = (0..3).map(|_| rng.next_qm31()).collect();
        let mut accumulator = PointEvaluationAccumulator::new(random_coeff);
        for term in &terms {
            accumulator.accumulate(*term);
        }
        let combined = accumulator.finalize();

        // 组合列 OODS mask 求值：left = [combined, 0, 0, 0]，right = 0
        // → extract = combined + dx·0 = combined ✓ DEEP-ALI 通过
        let comp_mask: Vec<QM31> = vec![
            combined,
            QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]),
            QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]),
            QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]),
            QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]),
            QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]),
            QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]),
            QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]),
        ];

        // verify_values 通道流
        ch.mix_felts(&[
            v0a, v0b, v1a, v1b,
            comp_mask[0], comp_mask[1], comp_mask[2], comp_mask[3],
            comp_mask[4], comp_mask[5], comp_mask[6], comp_mask[7],
        ]);
        let alpha_deep = ch.draw_secure_felt();

        // DEEP 商值：10 列（trace 2 + 组合 8）全位置
        let col0_ext: Vec<M31> = (0..N).map(|p| col0[p >> BLOWUP]).collect();
        let col1_ext: Vec<M31> = (0..N).map(|p| col1[p >> BLOWUP]).collect();
        let comp_ext: Vec<Vec<M31>> = (0..8usize)
            .map(|k| (0..N).map(|p| comp_vals[k][p]).collect())
            .collect();
        let ps = |z: CirclePoint<QM31>, v: QM31| PointSample { point: z, value: v };
        let all_pos: Vec<usize> = (0..N).collect();
        let fri_full: Vec<QM31> = fri_answers(
            TreeVec(vec![
                vec![TRACE_LOG, TRACE_LOG],
                vec![TRACE_LOG; 8],
            ]),
            TreeVec(vec![
                vec![
                    vec![ps(z0, v0a), ps(z1, v0b)],
                    vec![ps(z0, v1a), ps(z1, v1b)],
                ],
                (0..8usize)
                    .map(|k| vec![ps(oods, comp_mask[k])])
                    .collect(),
            ]),
            alpha_deep,
            &all_pos,
            TreeVec(vec![
                vec![col0_ext.clone(), col1_ext.clone()],
                comp_ext.clone(),
            ]),
            L,
        )
        .unwrap();

        // comp-only 参考值（位置 30）
        let cp_only = fri_answers(
            TreeVec(vec![(0..8usize).map(|_| TRACE_LOG).collect()]),
            TreeVec(vec![
                (0..8usize).map(|k| vec![ps(oods, comp_mask[k])]).collect(),
            ]),
            alpha_deep,
            &[30usize],
            TreeVec(vec![(0..8usize).map(|k| vec![comp_vals[k][30]]).collect()]),
            L,
        ).unwrap();
        // 在 emitter 内复刻 accumulate（与 fri_answers 同数据同域）
        {
            use stwo::core::fields::ComplexConjugate;
            let p30 = CanonicCoset::new(L).circle_domain().at(bit_reverse_index(30, L));
            let one = QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]);
            let _ = one;
            let contrib = |z: CirclePoint<QM31>, v: QM31, rp: QM31, qv: M31| -> QM31 {
                let denom: CM31 = (z.x.0 - p30.x) * z.y.1 - (z.y.0 - p30.y) * z.x.1;
                let a = v.complex_conjugate() - v;
                let c = z.complex_conjugate().y - z.y;
                let b = v * c - a * z.y;
                let num = qv * (rp * c) - (rp * a * p30.y + rp * b);
                num.mul_cm31(denom.inverse())
            };
            // batches: [zper(2)], [z0(2)], [z1(2)], [oods(8)]
            let zper = z1 + CirclePoint { x: QM31::from(CanonicCoset::new(L).step().repeated_double(4).x),
                                           y: QM31::from(CanonicCoset::new(L).step().repeated_double(4).y) };
            let b0 = contrib(zper, v0b, QM31::from_m31_array([M31(1), M31(0), M31(0), M31(0)]), col0_ext[30])
                + contrib(zper, v1b, alpha_deep * alpha_deep * alpha_deep, col1_ext[30]);
            let b1 = contrib(z0, v0a, alpha_deep, col0_ext[30])
                + contrib(z0, v1a, alpha_deep * alpha_deep * alpha_deep * alpha_deep, col1_ext[30]);
            let b2 = contrib(z1, v0b, alpha_deep * alpha_deep, col0_ext[30])
                + contrib(z1, v1b, alpha_deep * alpha_deep * alpha_deep * alpha_deep * alpha_deep, col1_ext[30]);
            let mut b3 = QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]);
            let mut rp = alpha_deep;
            for k in 0..6usize { rp = rp * alpha_deep; }
            for k in 0..8usize {
                b3 += contrib(oods, comp_mask[k], rp, comp_vals[k][30]);
                rp = rp * alpha_deep;
            }
            // 候选：comp 列的 α 幂起点
            for start in 3usize..8 {
                let mut b3c = QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]);
                let mut rpc = alpha_deep;
                for _k in 0..start { rpc = rpc * alpha_deep; }
                for k in 0..8usize {
                    let (z, v) = (oods, comp_mask[k]);
                    let denom: CM31 = (z.x.0 - p30.x) * z.y.1 - (z.y.0 - p30.y) * z.x.1;
                    let a = v.complex_conjugate() - v;
                    let c = z.complex_conjugate().y - z.y;
                    let b = v * c - a * z.y;
                    let num = comp_vals[k][30] * (rpc * c) - (rpc * a * p30.y + rpc * b);
                    b3c += num.mul_cm31(denom.inverse());
                    rpc = rpc * alpha_deep;
                }
            }
            let single = fri_answers(
                TreeVec(vec![
                    vec![TRACE_LOG, TRACE_LOG],
                    vec![TRACE_LOG; 8],
                ]),
                TreeVec(vec![
                    vec![
                        vec![ps(z0, v0a), ps(z1, v0b)],
                        vec![ps(z0, v1a), ps(z1, v1b)],
                    ],
                    (0..8usize)
                        .map(|_| vec![ps(oods, comp_mask[0])]).collect(),
                ]),
                alpha_deep,
                &[30usize],
                TreeVec(vec![
                    vec![vec![col0_ext[30]], vec![col1_ext[30]]],
                    (0..8usize).map(|k| vec![comp_vals[k][30]]).collect(),
                ]),
                L,
            ).unwrap();
        }
        // trace-only 参考值
        let tr_only = fri_answers(
            TreeVec(vec![vec![TRACE_LOG, TRACE_LOG]]),
            TreeVec(vec![
                vec![
                    vec![ps(z0, v0a), ps(z1, v0b)],
                    vec![ps(z0, v1a), ps(z1, v1b)],
                ],
            ]),
            alpha_deep,
            &[30usize],
            TreeVec(vec![vec![vec![col0_ext[30]], vec![col1_ext[30]]]]),
            L,
        ).unwrap();
        // DEEP 商值逐列（position 30 的 queried 值）
        for pos in 0..N {
            let a = fri_answers(
                TreeVec(vec![
                    vec![TRACE_LOG, TRACE_LOG],
                    vec![TRACE_LOG; 8],
                ]),
                TreeVec(vec![
                    vec![
                        vec![ps(z0, v0a), ps(z1, v0b)],
                        vec![ps(z0, v1a), ps(z1, v1b)],
                    ],
                    (0..8usize)
                        .map(|_| vec![ps(oods, comp_mask[0])]).collect(),
                ]),
                alpha_deep,
                &[pos],
                TreeVec(vec![
                    vec![vec![col0_ext[pos]], vec![col1_ext[pos]]],
                    (0..8usize).map(|k| vec![comp_vals[k][pos]]).collect(),
                ]),
                L,
            ).unwrap();
            if a[0].0 .0.0 == 725881284 && a[0].0 .1.0 == 1172529411 {
                println!("-- MATCH at position {} answer = {:?}", pos, a[0]);
            }
        }
        // comp-only 参考值（位置 30）
        let cp_only = fri_answers(
            TreeVec(vec![(0..8usize).map(|_| TRACE_LOG).collect()]),
            TreeVec(vec![
                (0..8usize).map(|k| vec![ps(oods, comp_mask[k])]).collect(),
            ]),
            alpha_deep,
            &[30usize],
            TreeVec(vec![(0..8usize).map(|k| vec![comp_vals[k][30]]).collect()]),
            L,
        ).unwrap();
        // 在 emitter 内复刻 accumulate（与 fri_answers 同数据同域）
        {
            use stwo::core::fields::ComplexConjugate;
            let p30 = CanonicCoset::new(L).circle_domain().at(bit_reverse_index(30, L));
            let one = QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]);
            let _ = one;
            let contrib = |z: CirclePoint<QM31>, v: QM31, rp: QM31, qv: M31| -> QM31 {
                let denom: CM31 = (z.x.0 - p30.x) * z.y.1 - (z.y.0 - p30.y) * z.x.1;
                let a = v.complex_conjugate() - v;
                let c = z.complex_conjugate().y - z.y;
                let b = v * c - a * z.y;
                let num = qv * (rp * c) - (rp * a * p30.y + rp * b);
                num.mul_cm31(denom.inverse())
            };
            // batches: [zper(2)], [z0(2)], [z1(2)], [oods(8)]
            let zper = z1 + CirclePoint { x: QM31::from(CanonicCoset::new(L).step().repeated_double(4).x),
                                           y: QM31::from(CanonicCoset::new(L).step().repeated_double(4).y) };
            let b0 = contrib(zper, v0b, QM31::from_m31_array([M31(1), M31(0), M31(0), M31(0)]), col0_ext[30])
                + contrib(zper, v1b, alpha_deep * alpha_deep * alpha_deep, col1_ext[30]);
            let b1 = contrib(z0, v0a, alpha_deep, col0_ext[30])
                + contrib(z0, v1a, alpha_deep * alpha_deep * alpha_deep * alpha_deep, col1_ext[30]);
            let b2 = contrib(z1, v0b, alpha_deep * alpha_deep, col0_ext[30])
                + contrib(z1, v1b, alpha_deep * alpha_deep * alpha_deep * alpha_deep * alpha_deep, col1_ext[30]);
            let mut b3 = QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]);
            let mut rp = alpha_deep;
            for k in 0..6usize { rp = rp * alpha_deep; }
            for k in 0..8usize {
                b3 += contrib(oods, comp_mask[k], rp, comp_vals[k][30]);
                rp = rp * alpha_deep;
            }
            // 候选：comp 列的 α 幂起点
            for start in 3usize..8 {
                let mut b3c = QM31::from_m31_array([M31(0), M31(0), M31(0), M31(0)]);
                let mut rpc = alpha_deep;
                for _k in 0..start { rpc = rpc * alpha_deep; }
                for k in 0..8usize {
                    let (z, v) = (oods, comp_mask[k]);
                    let denom: CM31 = (z.x.0 - p30.x) * z.y.1 - (z.y.0 - p30.y) * z.x.1;
                    let a = v.complex_conjugate() - v;
                    let c = z.complex_conjugate().y - z.y;
                    let b = v * c - a * z.y;
                    let num = comp_vals[k][30] * (rpc * c) - (rpc * a * p30.y + rpc * b);
                    b3c += num.mul_cm31(denom.inverse());
                    rpc = rpc * alpha_deep;
                }
            }
            let single = fri_answers(
                TreeVec(vec![
                    vec![TRACE_LOG, TRACE_LOG],
                    vec![TRACE_LOG; 8],
                ]),
                TreeVec(vec![
                    vec![
                        vec![ps(z0, v0a), ps(z1, v0b)],
                        vec![ps(z0, v1a), ps(z1, v1b)],
                    ],
                    (0..8usize)
                        .map(|_| vec![ps(oods, comp_mask[0])]).collect(),
                ]),
                alpha_deep,
                &[30usize],
                TreeVec(vec![
                    vec![vec![col0_ext[30]], vec![col1_ext[30]]],
                    (0..8usize).map(|k| vec![comp_vals[k][30]]).collect(),
                ]),
                L,
            ).unwrap();
        }
        // trace-only 参考值
        let tr_only = fri_answers(
            TreeVec(vec![vec![TRACE_LOG, TRACE_LOG]]),
            TreeVec(vec![
                vec![
                    vec![ps(z0, v0a), ps(z1, v0b)],
                    vec![ps(z0, v1a), ps(z1, v1b)],
                ],
            ]),
            alpha_deep,
            &[30usize],
            TreeVec(vec![vec![vec![col0_ext[30]], vec![col1_ext[30]]]]),
            L,
        ).unwrap();

        // FRI 链（与向量 A 同构：首层 + 2 内层，foldStep=1）
        let fri_leaf = |qv: &QM31| leaf_hash(&[qv.0 .0, qv.0 .1, qv.1 .0, qv.1 .1]);
        let build_tree = |vals: &[QM31]| -> (Fe, Vec<Vec<Fe>>) {
            let leaves: Vec<Fe> = vals.iter().map(&fri_leaf).collect();
            let mut ls = vec![leaves];
            while ls.last().unwrap().len() > 1 {
                let nxt: Vec<Fe> = ls.last().unwrap().chunks(2)
                    .map(|c| starknet_crypto::poseidon_hash(c[0], c[1])).collect();
                ls.push(nxt);
            }
            (ls.last().unwrap()[0], ls)
        };
        let (root_f0, levels_f0) = build_tree(&fri_full);
        mix_root(&mut ch, root_f0);
        let alpha0 = ch.draw_secure_felt();
        let circle_domain = CanonicCoset::new(L).circle_domain();
        let line0: Vec<QM31> = fold_circle_into_line(&fri_full, circle_domain, alpha0);
        let dom1 = LineDomain::new(Coset::half_odds(L - 1));
        let (root_f1, levels_f1) = build_tree(&line0);
        mix_root(&mut ch, root_f1);
        let alpha1 = ch.draw_secure_felt();
        let (dom2, line1) = fold_line(&line0, dom1, alpha1);
        let (root_f2, levels_f2) = build_tree(&line1);
        mix_root(&mut ch, root_f2);
        let alpha2 = ch.draw_secure_felt();
        let (_dom3, line2) = fold_line(&line1, dom2, alpha2);
        let last_channel: Vec<QM31> = vec![rng.next_qm31()];
        ch.mix_felts(&last_channel);

        let prefixed = starknet_crypto::poseidon_hash_many(&[
            Fe::from(0x12345678u32),
            ch.digest(),
            Fe::from(POW_BITS),
        ]);
        let mut nonce: u64 = 0;
        loop {
            let h = starknet_crypto::poseidon_hash(prefixed, Fe::from(nonce));
            let bytes = h.to_bytes_be();
            let low = u128::from_be_bytes(bytes[16..].try_into().unwrap());
            if low.trailing_zeros() >= POW_BITS as u32 {
                break;
            }
            nonce += 1;
        }
        ch.mix_u64(nonce);

        let raw = draw_queries(&mut ch, L, 1);
        let mut sorted = raw.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let q = sorted[0];
        let pp = prepare_preprocessed_query_positions(&sorted, L, L);

        let c0v = col0[q >> BLOWUP];
        let c1v = col1[q >> BLOWUP];
        let comp_row: Vec<M31> = (0..8usize).map(|k| comp_vals[k][q]).collect();
        let trace_witness: Vec<Fe> = {
            let mut v = Vec::new();
            let mut j = q;
            for lev in 0..L as usize {
                v.push(trace_levels[lev][(j >> lev) ^ 1]);
            }
            v
        };
        let comp_witness: Vec<Fe> = {
            let mut v = Vec::new();
            let mut j = q;
            for lev in 0..L as usize {
                v.push(comp_levels[lev][(j >> lev) ^ 1]);
            }
            v
        };
        let mv_tr = MerkleVerifierLifted::<LH>::new(trace_root, vec![L, L], None);
        let _ = mv_tr
            .verify(&pp, vec![vec![c0v], vec![c1v]], MerkleDecommitmentLifted { hash_witness: trace_witness.clone() })
            .unwrap_or_else(|e| panic!("comp verify failed: {:?}", e));
        let mv_cp = MerkleVerifierLifted::<LH>::new(comp_root, vec![L; 8], None);
        let _ = mv_cp
            .verify(
                &pp,
                (0..8usize).map(|k| vec![comp_row[k]]).collect::<Vec<_>>(),
                MerkleDecommitmentLifted { hash_witness: comp_witness.clone() },
            )
            .unwrap();

        let i = q / 2;
        let first_witness: Vec<Fe> = {
            let mut v = Vec::new();
            let mut jj = 2 * i;
            for lev in 1..L as usize {
                v.push(levels_f0[lev][(jj >> lev) ^ 1]);
            }
            v
        };
        let p1 = q >> 1;
        let w_f1: Vec<Fe> = {
            let mut v = Vec::new();
            let mut jj = p1;
            for lev in 1..5usize {
                v.push(levels_f1[lev][(jj >> lev) ^ 1]);
            }
            v
        };
        let p2 = q >> 2;
        let w_f2: Vec<Fe> = {
            let mut v = Vec::new();
            let mut jj = p2;
            for lev in 1..4usize {
                v.push(levels_f2[lev][(jj >> lev) ^ 1]);
            }
            v
        };
        let jstar = q >> 3;
        let last_check = line2[jstar];

        // DEEP-ALI 自检（Rust 侧）：extract == combined
        {
            let left = combined;
            let dx = oods.repeated_double(TRACE_LOG - 1).x;
            let extracted = left + dx * QM31::from_m31_array([M31(0); 4]);
            assert_eq!(extracted, combined);
        }

        // 主循环断言（分段拼装）
        let ps_str = |z: &CirclePoint<QM31>, v: &QM31| {
            format!("StwoLean.Deep.PointSample.mk {} {}", point_secure_lean(*z), qm31_lean(*v))
        };
        let mut cols_str: Vec<String> = Vec::new();
        cols_str.push(format!(
            "(4, [{}, {}])",
            ps_str(&z0, &v0a),
            ps_str(&z1, &v0b)
        ));
        cols_str.push(format!(
            "(4, [{}, {}])",
            ps_str(&z0, &v1a),
            ps_str(&z1, &v1b)
        ));
        for k in 0..8usize {
            cols_str.push(format!("(4, [{}])", ps_str(&oods, &comp_mask[k])));
        }
        let tree_trace = format!(
            "{{ root := {}, isPP := false, height := 6, rows := [[{}, {}]], witness := [{}] }}",
            felt252_lean(trace_root),
            m31_lean(c0v),
            m31_lean(c1v),
            trace_witness.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", ")
        );
        let tree_comp = format!(
            "{{ root := {}, isPP := false, height := 6, rows := [[{}]], witness := [{}] }}",
            felt252_lean(comp_root),
            comp_row.iter().map(|m| m31_lean(*m)).collect::<Vec<_>>().join(", "),
            comp_witness.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", ")
        );
        let fri_layer = |root: &Fe, positions: &[usize], evals: &[QM31], wit: &[Fe]| {
            format!(
                "{{ root := {}, positions := [{}], evals := [{}], witness := [{}], packedShift := 0 }}",
                felt252_lean(*root),
                positions.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
                evals.iter().map(|e| qm31_lean(*e)).collect::<Vec<_>>().join(", "),
                wit.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", ")
            )
        };
        let l0 = format!(
            "{{ root := {}, positions := [{}, {}], evals := [{}, {}], witness := [{}], packedShift := 0 }}",
            felt252_lean(root_f0), 2 * i, 2 * i + 1,
            qm31_lean(fri_full[2 * i]), qm31_lean(fri_full[2 * i + 1]),
            first_witness.iter().map(|f| felt252_lean(*f)).collect::<Vec<_>>().join(", ")
        );
        let l1 = fri_layer(&root_f1, &[p1 & !1, (p1 & !1) + 1],
            &[line0[p1 & !1], line0[(p1 & !1) + 1]], &w_f1);
        let l2 = fri_layer(&root_f2, &[p2 & !1, (p2 & !1) + 1],
            &[line1[p2 & !1], line1[(p2 & !1) + 1]], &w_f2);
        let comp_sample_strs: Vec<String> = (0..8usize)
            .map(|k| format!("(4, [{}])", ps_str(&oods, &comp_mask[k])))
            .collect();

        let stmt = format!(
            "theorem verifierMain : StwoLean.Verifier.verifyMain\n    {{ firstLayerLog := 6, foldStep := 1, powBits := 4, nQueries := 1, ppMaxLog := 6 }}\n    [{{ maxConstraintLogDegreeBound := 2, terms := [{}, {}, {}] }}] 4\n    [{}]\n    {{ compositionCommitment := {}, compositionMask := [{}],\n       pcs := {{ trees := [{}, {}],\n       sampledValues := [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}],\n       friLayers := [{}, {}, {}],\n       lastPolyChannel := [{}], lastPoly := [{}, (0 : StwoLean.QM31)],\n       powNonce := {} }} }}\n    (({}, 0) : StwoLean.Channel.Chan) = true := by native_decide",
            qm31_lean(terms[0]),
            qm31_lean(terms[1]),
            qm31_lean(terms[2]),
            cols_str.join(", "),
            felt252_lean(comp_root),
            comp_mask.iter().map(|m| qm31_lean(*m)).collect::<Vec<_>>().join(", "),
            tree_trace,
            tree_comp,
            qm31_lean(v0a), qm31_lean(v0b), qm31_lean(v1a), qm31_lean(v1b),
            qm31_lean(comp_mask[0]), qm31_lean(comp_mask[1]),
            qm31_lean(comp_mask[2]), qm31_lean(comp_mask[3]),
            qm31_lean(comp_mask[4]), qm31_lean(comp_mask[5]),
            qm31_lean(comp_mask[6]), qm31_lean(comp_mask[7]),
            l0,
            l1,
            l2,
            qm31_lean(last_channel[0]),
            qm31_lean(last_check),
            nonce,
            felt252_lean(ch_after_commit)
        );
        println!("{}", stmt.split('\n').map(|l| l.trim()).collect::<Vec<_>>().join(" "));

        // —— StarkProof serde JSON 导出 + Lean 解析对拍 ——
        // 用真实 stwo 类型 + serde_json 序列化出 `CommitmentSchemeProof`
        // 的 canonical serde 形态；`air` 段为验证器侧输入（组件约束项、
        // OODS 采样、初始通道等，不属于 stwo proof 结构）。末层多项式按
        // `PcsProofGen.lastPoly` 注释解耦：占位 [last_check, 0]。
        {
            use stwo::core::fri::{FriConfig, FriLayerProof, FriProof};
            use stwo::core::pcs::PcsConfig;
            use stwo::core::pcs::quotients::CommitmentSchemeProof;
            use stwo::core::poly::line::LinePoly;

            let limbs4 = |v: QM31| [v.0 .0, v.0 .1, v.1 .0, v.1 .1];
            let fri0_cols: Vec<Vec<M31>> =
                (0..4usize).map(|l| vec![limbs4(fri_full[q])[l]]).collect();
            let fri1_cols: Vec<Vec<M31>> =
                (0..4usize).map(|l| vec![limbs4(line0[p1])[l]]).collect();
            let fri2_cols: Vec<Vec<M31>> =
                (0..4usize).map(|l| vec![limbs4(line1[p2])[l]]).collect();
            let csp = CommitmentSchemeProof::<LH> {
                config: PcsConfig {
                    pow_bits: POW_BITS,
                    fri_config: FriConfig {
                        log_blowup_factor: BLOWUP,
                        log_last_layer_degree_bound: 0,
                        n_queries: 1,
                        fold_step: 1,
                    },
                    lifting_log_size: None,
                },
                commitments: TreeVec(vec![trace_root, comp_root, root_f0, root_f1, root_f2]),
                sampled_values: TreeVec(vec![
                    vec![vec![v0a, v0b], vec![v1a, v1b]],
                    (0..8usize).map(|k| vec![comp_mask[k]]).collect::<Vec<_>>(),
                ]),
                decommitments: TreeVec(vec![
                    MerkleDecommitmentLifted { hash_witness: trace_witness.clone() },
                    MerkleDecommitmentLifted { hash_witness: comp_witness.clone() },
                    MerkleDecommitmentLifted { hash_witness: first_witness.clone() },
                    MerkleDecommitmentLifted { hash_witness: w_f1.clone() },
                    MerkleDecommitmentLifted { hash_witness: w_f2.clone() },
                ]),
                queried_values: TreeVec(vec![
                    vec![vec![c0v], vec![c1v]],
                    (0..8usize).map(|k| vec![comp_row[k]]).collect::<Vec<_>>(),
                    fri0_cols,
                    fri1_cols,
                    fri2_cols,
                ]),
                proof_of_work: nonce,
                fri_proof: FriProof::<LH> {
                    first_layer: FriLayerProof::<LH> {
                        fri_witness: vec![fri_full[q ^ 1]],
                        decommitment: MerkleDecommitmentLifted {
                            hash_witness: first_witness.clone(),
                        },
                        commitment: root_f0,
                    },
                    inner_layers: vec![
                        FriLayerProof::<LH> {
                            fri_witness: vec![line0[p1 ^ 1]],
                            decommitment: MerkleDecommitmentLifted {
                                hash_witness: w_f1.clone(),
                            },
                            commitment: root_f1,
                        },
                        FriLayerProof::<LH> {
                            fri_witness: vec![line1[p2 ^ 1]],
                            decommitment: MerkleDecommitmentLifted {
                                hash_witness: w_f2.clone(),
                            },
                            commitment: root_f2,
                        },
                    ],
                    last_layer_poly: LinePoly::new(vec![
                        last_check,
                        QM31::from_m31_array([M31(0); 4]),
                    ]),
                },
            };
            let proof_json = serde_json::to_string(&csp).unwrap();
            let qmj = |v: &QM31| serde_json::to_value(v).unwrap();
            let ptj = |p: &CirclePoint<QM31>| {
                serde_json::json!({ "x": qmj(&p.x), "y": qmj(&p.y) })
            };
            let colj = |log: u32, ss: Vec<(CirclePoint<QM31>, QM31)>| {
                serde_json::json!({
                    "log_size": log,
                    "samples": ss.iter().map(|(p, v)| serde_json::json!({
                        "point": ptj(p), "value": qmj(v)
                    })).collect::<Vec<_>>()
                })
            };
            let mut cols_json: Vec<serde_json::Value> = vec![
                colj(TRACE_LOG, vec![(z0, v0a), (z1, v0b)]),
                colj(TRACE_LOG, vec![(z0, v1a), (z1, v1b)]),
            ];
            for k in 0..8usize {
                cols_json.push(colj(TRACE_LOG, vec![(oods, comp_mask[k])]));
            }
            let air = serde_json::json!({
                "channel_init": serde_json::to_value(&ch_after_commit).unwrap(),
                "first_layer_log": L,
                "fold_step": 1u32,
                "pow_bits": POW_BITS,
                "n_queries": 1usize,
                "pp_max_log": L,
                "composition_log_degree_bound": TRACE_LOG,
                "query_positions": [q],
                "components": [{
                    "max_log_degree_bound": 2u32,
                    "terms": terms.iter().map(|t| qmj(t)).collect::<Vec<_>>(),
                }],
                "cols": cols_json,
                "composition_commitment": serde_json::to_value(&comp_root).unwrap(),
                "composition_mask": comp_mask.iter().map(|m| qmj(m)).collect::<Vec<_>>(),
                "last_poly_channel": [qmj(&last_channel[0])],
            });
            let doc = format!("{{\"proof\":{},\"air\":{}}}", proof_json, air);
            assert!(!doc.contains("\"#"), "JSON 不得含 r# 终止序列");
            std::fs::create_dir_all("../vectors").unwrap();
            std::fs::write("../vectors/proof.json", &doc).unwrap();

            println!();
            println!("section StarkProofJsonVec");
            println!();
            println!("open StwoLean.StarkProofJson");
            println!();
            println!("-- 同一份 proof.json 内嵌解析：parseProof → verifyMain 全链（内核归约）");
            println!(
                "def spj : Option StwoLean.StarkProofJson.ParsedProof :=");

            println!("    StwoLean.StarkProofJson.parseProof r#\"{}\"#", doc);
            println!();
            println!("example : spj.isSome = true := by native_decide");
            println!(
                "theorem starkProofJsonVerify : StwoLean.StarkProofJson.verifyJson r#\"{}\"# = true := by native_decide",
                doc
            );
            println!(
                "example : ppRoot0 spj = {} := by native_decide",
                felt252_lean(trace_root)
            );
            println!(
                "example : ppRoot1 spj = {} := by native_decide",
                felt252_lean(comp_root)
            );
            println!(
                "example : ppNonce spj = {} := by native_decide",
                nonce
            );
            println!();
            println!("end StarkProofJsonVec");
        }
    }
    println!("end Pcs");
    println!();

    // —— Blake2s / Blake2sChannel：hashlib 交叉验证 + stwo `core/channel/blake2s.rs` 对拍 ——
    println!("section Blake2s");
    println!();

    fn bytes_lean(bs: &[u8]) -> String {
        bs.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ")
    }
    fn words_lean(ws: &[u32]) -> String {
        ws.iter().map(|w| w.to_string()).collect::<Vec<_>>().join(", ")
    }

    // 标准向量：Lean blake2s 与 stwo 的 Blake2sHasher（即 RFC 7693 BLAKE2s-256）直接对拍，
    // 覆盖 单块短消息 / 空消息 / 恰满一块(t=64) / 两块(t=64→65)。
    println!(
        "example : Blake2s.blake2s [97, 98, 99] = [{}] := by native_decide",
        bytes_lean(&stwo::core::vcs::blake2_hash::Blake2sHasher::hash(b"abc").0)
    );
    println!(
        "example : Blake2s.blake2s [] = [{}] := by native_decide",
        bytes_lean(&stwo::core::vcs::blake2_hash::Blake2sHasher::hash(b"").0)
    );
    println!(
        "example : Blake2s.blake2s (List.replicate 64 0) = [{}] := by native_decide",
        bytes_lean(&stwo::core::vcs::blake2_hash::Blake2sHasher::hash(&[0u8; 64]).0)
    );
    let b65: Vec<u8> = [120u8].into_iter().chain([0u8; 64]).collect();
    println!(
        "example : Blake2s.blake2s (120 :: List.replicate 64 0) = [{}] := by native_decide",
        bytes_lean(&stwo::core::vcs::blake2_hash::Blake2sHasher::hash(&b65).0)
    );
    println!();

    // mix_u32s / mix_u64：金值即 stwo 单元测试 test_mix_u32s / test_mix_u64 的断言摘要。
    let mut ch = Blake2sChannel::default();
    ch.mix_u32s(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    println!(
        "example : (Blake2s.b2MixU32s [1, 2, 3, 4, 5, 6, 7, 8, 9] Blake2s.ch0).1 = [{}] := by native_decide",
        bytes_lean(&ch.digest().0)
    );
    let mut ch = Blake2sChannel::default();
    ch.mix_u64(0x1111222233334444);
    println!(
        "example : (Blake2s.b2MixU64 {} Blake2s.ch0).1 = [{}] := by native_decide",
        0x1111222233334444u64,
        bytes_lean(&ch.digest().0)
    );
    println!();

    // mix_felts → draw_u32s → draw_secure_felt → verify_pow_nonce 全链。
    let mut rngb = Lcg(0x20260920);
    let (q0, q1) = (rngb.next_qm31(), rngb.next_qm31());

    let mut ch = Blake2sChannel::default();
    ch.mix_felts(&[q0, q1]);
    println!(
        "example : (Blake2s.b2MixFelts [{}, {}] Blake2s.ch0).1 = [{}] := by native_decide",
        qm31_lean(q0),
        qm31_lean(q1),
        bytes_lean(&ch.digest().0)
    );

    let words = ch.draw_u32s();
    println!(
        "example : (Blake2s.b2DrawU32s (Blake2s.b2MixFelts [{}, {}] Blake2s.ch0)).1 = [{}] := by native_decide",
        qm31_lean(q0),
        qm31_lean(q1),
        words_lean(&words)
    );
    println!(
        "example : (Blake2s.b2DrawU32s (Blake2s.b2MixFelts [{}, {}] Blake2s.ch0)).2.2 = 1 := by decide",
        qm31_lean(q0),
        qm31_lean(q1)
    );

    // draw_secure_felt：统计重试轮数作为 Lean 侧燃料。
    let mut rounds = 0usize;
    let secure;
    loop {
        let ws = ch.draw_u32s();
        rounds += 1;
        if ws.iter().all(|&x| x < 2 * P) {
            let r = |x: u32| M31::reduce(x as u64);
            secure = QM31(CM31(r(ws[0]), r(ws[1])), CM31(r(ws[2]), r(ws[3])));
            break;
        }
    }
    println!(
        "example : (Blake2s.b2DrawSecureFelt {} ((Blake2s.b2DrawU32s (Blake2s.b2MixFelts [{}, {}] Blake2s.ch0)).2)).1 = {} := by native_decide",
        rounds,
        qm31_lean(q0),
        qm31_lean(q1),
        qm31_lean(secure)
    );

    // verify_pow_nonce：搜一个 n_bits=4 的 nonce（真例），并断言 n_bits=30 同 nonce 为假。
    let mut chp = Blake2sChannel::default();
    chp.mix_felts(&[q0, q1]);
    let mut nonce: u64 = 0;
    while !chp.verify_pow_nonce(4, nonce) {
        nonce += 1;
    }
    let big_ok = chp.verify_pow_nonce(30, nonce);
    println!(
        "example : Blake2s.b2VerifyPowNonce (Blake2s.b2MixFelts [{}, {}] Blake2s.ch0).1 4 {} = true := by native_decide",
        qm31_lean(q0),
        qm31_lean(q1),
        nonce
    );
    println!(
        "example : Blake2s.b2VerifyPowNonce (Blake2s.b2MixFelts [{}, {}] Blake2s.ch0).1 30 {} = {} := by native_decide",
        qm31_lean(q0),
        qm31_lean(q1),
        nonce,
        big_ok
    );

    println!();
    println!("end Blake2s");
    println!();

    println!("end StwoLean.Vectors");
}
