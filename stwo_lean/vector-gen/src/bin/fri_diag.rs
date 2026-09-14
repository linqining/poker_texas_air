// 完整模拟 Lean friVerify 的每层语义（merkle pathRoot + foldPair），定位分歧。
use stwo::core::circle::{CirclePointIndex, Coset};
use stwo::core::fields::cm31::CM31;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::fields::Field;
use stwo::core::fri::fold_line;
use stwo::core::poly::line::LineDomain;
use stwo::core::utils::bit_reverse_index;
use stwo::core::vcs::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo::core::vcs::MerkleHasher;

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
        M31(((self.next_u64() >> 33) as u32) % 2147483647)
    }
    fn next_cm31(&mut self) -> CM31 {
        CM31(self.next_m31(), self.next_m31())
    }
    fn next_qm31(&mut self) -> QM31 {
        QM31(self.next_cm31(), self.next_cm31())
    }
}

fn qmh(q: &QM31) -> String {
    format!("[{},{},{},{}]", q.0.0.0, q.0.1.0, q.1.0.0, q.1.1.0)
}
fn hexf(f: starknet_ff::FieldElement) -> String {
    let b = f.to_bytes_be();
    let s: String = b.iter().map(|y| format!("{:02x}", y)).collect();
    s.trim_start_matches('0').to_string()
}

fn main() {
    let mut rng = Lcg(0xabcdef);
    let mut evals: Vec<QM31> = (0..8).map(|_| rng.next_qm31()).collect();
    let alphas: Vec<QM31> = (0..3).map(|_| rng.next_qm31()).collect();
    let coset = Coset::new(CirclePointIndex(1), 3);
    let mut domain = LineDomain::new(coset);
    let mut idx: usize = 5;
    let mut log: u32 = 3;

    for layer in 0..3 {
        // ---- emitter 的树构造（bit-reverse 叶序）----
        let leaf_vals: Vec<starknet_ff::FieldElement> = evals
            .iter()
            .map(|q| Poseidon252MerkleHasher::hash_node(None, &[q.0.0, q.0.1, q.1.0, q.1.1]))
            .collect();
        let br: Vec<usize> = (0..evals.len()).map(|i| bit_reverse_index(i, log)).collect();
        let leaf_hashes: Vec<starknet_ff::FieldElement> =
            br.iter().map(|&i| leaf_vals[i]).collect();
        // 树
        let mut levels = vec![leaf_hashes.clone()];
        let mut cur = leaf_hashes.clone();
        while cur.len() > 1 {
            let nxt: Vec<starknet_ff::FieldElement> = cur
                .chunks(2)
                .map(|c| Poseidon252MerkleHasher::hash_node(Some((c[0], c[1])), &[]))
                .collect();
            cur = nxt;
            levels.push(cur.clone());
        }
        let root = levels[levels.len() - 1][0];
        for (li, lv) in levels.iter().enumerate() {
            for (k, v) in lv.iter().enumerate() {
                println!("  MERKLE L{}[{}] = {}", li, k, hexf(*v));
            }
        }

        // ---- Lean friLayerVerifyAndFold 语义 ----
        let leaf_idx = bit_reverse_index(idx, log);
        let pair_start = 2 * (idx / 2);
        let x = domain.at(bit_reverse_index(pair_start, log));
        let xinv = x.inverse();

        // pathSelf 链重算根（从叶 idx 的兄弟链）
        let mut pth_self: Vec<starknet_ff::FieldElement> = Vec::new();
        let mut j = leaf_idx;
        for level in &levels {
            if level.len() == 1 {
                break;
            }
            pth_self.push(level[j ^ 1]);
            j >>= 1;
        }
        let mut r = leaf_hashes[leaf_idx];
        let mut jj = leaf_idx;
        for sib in &pth_self {
            if jj % 2 == 0 {
                r = Poseidon252MerkleHasher::hash_node(Some((r, *sib)), &[]);
            } else {
                r = Poseidon252MerkleHasher::hash_node(Some((*sib, r)), &[]);
            }
            jj >>= 1;
        }
        for (k, lh) in leaf_hashes.iter().enumerate() {
            println!("  L{} leaf[{}] = {}", layer, k, hexf(*lh));
        }
        println!(
            "layer {}: leaf_idx={} pathRoot==root? {} root={}",
            layer,
            leaf_idx,
            r == root,
            hexf(root)
        );
        // 折叠输出
        let (d2, fl) = fold_line(&evals, domain, alphas[layer]);
        let fold_out = fl[idx / 2];
        println!(
            "  fold_line output[{}] = {}; alpha = {}",
            idx / 2,
            qmh(&fold_out),
            qmh(&alphas[layer])
        );
        evals = fl;
        domain = d2;
        idx /= 2;
        log -= 1;
    }
}
