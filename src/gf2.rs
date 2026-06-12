//! Minimal GF(2) linear-algebra solver.
//!
//! Linear PRNGs (xorshift128+ and friends) are linear maps over GF(2), so every
//! observed output bit is a linear equation in the seed bits. With ≥128
//! independent equations we recover a 128-bit seed by Gaussian elimination — no
//! SAT/SMT solver required. Equations are `(coeff, rhs)` where `coeff` is a
//! 128-bit mask over the seed bits and `rhs` is the observed bit.

/// Solve a system over 128 unknowns. Returns the seed (bit i = unknown i), or
/// `None` if the equations are inconsistent.
pub fn solve_128(mut mat: Vec<(u128, u8)>) -> Option<u128> {
    let mut pivot_for_col = [usize::MAX; 128];
    let mut rank = 0usize;
    for col in 0..128 {
        let Some(sel) = (rank..mat.len()).find(|&k| (mat[k].0 >> col) & 1 == 1) else {
            continue;
        };
        mat.swap(rank, sel);
        for k in 0..mat.len() {
            if k != rank && (mat[k].0 >> col) & 1 == 1 {
                mat[k].0 ^= mat[rank].0;
                mat[k].1 ^= mat[rank].1;
            }
        }
        pivot_for_col[col] = rank;
        rank += 1;
    }
    if mat.iter().any(|&(c, b)| c == 0 && b == 1) {
        return None;
    }
    let mut sol: u128 = 0;
    for col in 0..128 {
        let pr = pivot_for_col[col];
        if pr != usize::MAX && mat[pr].1 == 1 {
            sol |= 1u128 << col;
        }
    }
    Some(sol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_a_known_system() {
        // Unknown seed; build full-rank identity-ish equations and recover it.
        let seed: u128 = 0xdead_beef_1234_5678_9abc_def0_0f0f_1122;
        let mut rows = Vec::new();
        for i in 0..128 {
            let coeff = 1u128 << i;
            rows.push((coeff, ((seed >> i) & 1) as u8));
        }
        assert_eq!(solve_128(rows), Some(seed));
    }
}
