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

use stwo::core::channel::{Channel, Poseidon252Channel};
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
    println!("import StwoLean.Poseidon252");
    println!("import StwoLean.Channel");
    println!("import StwoLean.Merkle");
    println!("import StwoLean.FriCore");
    println!("import StwoLean.FriVerifier");
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
        let mut rng = Lcg(0xfeed);
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
        let mut rng = Lcg(0xabcdef);
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
            // 承诺叶按 bit-reverse 排列（对应 stwo fold_line 输出后
            // 的 `bit_reverse_column`）；承诺叶[j] 的域点 =
            // domain.at(bit_reverse_index(j, log))。
            let log_l = (3 - layer) as u32;
            let mut leaf_vals: Vec<starknet_ff::FieldElement> =
                ev.iter().map(&layer_leaf).collect();
            let br: Vec<usize> = (0..ev.len())
                .map(|i| bit_reverse_index(i, log_l))
                .collect();
            leaf_vals = br.iter().map(|&i| leaf_vals[i]).collect();
            let leaf_hashes: Vec<starknet_ff::FieldElement> = leaf_vals;
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
            // idx >> layer 的路径：每层兄弟（单元素末层无兄弟，跳过）
            // 承诺叶为 bit-reverse 排列，叶下标 = bitrev(自然位置, log)。
            let mut pth: Vec<starknet_ff::FieldElement> = Vec::new();
            let mut j = bit_reverse_index(idx >> layer, log_i as u32);
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
                    let mut jj = bit_reverse_index(j, (3 - layer) as u32);
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
                    let mut jj = bit_reverse_index(j ^ 1, (3 - layer) as u32);
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
    println!("end StwoLean.Vectors");
}
