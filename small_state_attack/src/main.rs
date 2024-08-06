//! A demonstration of an attack against the MS PRG with a small state.

mod msprg;

use crate::msprg::{State, Version};

use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use rsa::BigUint;

fn main() {
    println!("Small State Attack");
    match small_state_attack(2048, &BigUint::from(3u32)) {
        Some(state) => println!("Recovered state: {state}"),
        None => println!("Small state attack failed"),
    };

    println!("Improved Small State Attack");
    match improved_small_state_attack(2048, &BigUint::from(3u32), 1) {
        Some(state) => println!("Recovered state: {state}"),
        None => println!("Improved small state attack failed"),
    };
}

/// Performs the small state attack.
fn small_state_attack(n: usize, e: &BigUint) -> Option<BigUint> {
    let r = (BigUint::from(n - 1) / e).to_usize()?;
    let k = n - r;
    let mut msprg = State::new(n, e, k, Version::Ms91);
    println!("{msprg}");

    let b = msprg.next()?;
    println!("Output: {b}");
    let (s0, bits) = hensel_solve(e, &b, k)?;
    (r <= bits).then_some(s0 & ((BigUint::one() << r) - 1u32))
}

/// Performs the improved small state attack.
fn improved_small_state_attack(n: usize, e: &BigUint, m: u32) -> Option<BigUint> {
    let r = (BigUint::from(n - 1 + usize::try_from(m * n.ilog2()).ok()?) / e).to_usize()?;
    let k = n - r;
    let mut msprg = State::new(n, e, k, Version::Ms91);
    println!("{msprg}");

    let b = msprg.next()?;
    println!("Output: {b}");

    let k_bitmask = (BigUint::one() << k) - 1u32;
    let r_bitmask = (BigUint::one() << r) - 1u32;
    let bound = msprg.modulus() * n.pow(m);
    (0..n.pow(m)).find_map(|c| {
        let target = &b + msprg.modulus() * c;
        let (s0, bits) = hensel_solve(e, &target, k)?;
        let candidate = s0 & &r_bitmask;
        let (quot, rem) = candidate.modpow(e, &bound).div_rem(msprg.modulus());
        (r <= bits && quot == BigUint::from(c) && rem & &k_bitmask == b).then_some(candidate)
    })
}

/// Finds a solution to x^e = b (mod 2^k), where e is odd.
///
/// If the solution exists, the solution and number of bits where it is unique
/// is returned.
fn hensel_solve(e: &BigUint, b: &BigUint, mut k: usize) -> Option<(BigUint, usize)> {
    if e.is_even() {
        return None;
    }

    let mut target = b & ((BigUint::one() << k) - 1u32);
    let Some(zeros) = target.trailing_zeros() else {
        // If the target is zero, then the solution is zero mod 2^(k / e).
        return Some((BigUint::zero(), (BigUint::from(k).div_ceil(e)).to_usize()?));
    };

    target >>= zeros;
    k -= zeros;
    let sol_zeros = {
        let (sol_zeros, rem) = BigUint::from(zeros).div_rem(e);
        if !rem.is_zero() {
            return None;
        };
        sol_zeros.to_usize()?
    };

    // Solve for the odd part.
    let mut sol = BigUint::one();
    for i in 1..k {
        let two_pow_i_plus_one = BigUint::one() << (i + 1);
        sol += (sol.modpow(e, &two_pow_i_plus_one) + &two_pow_i_plus_one
            - (&target & (&two_pow_i_plus_one - 1u32)))
            & (BigUint::one() << i);
    }

    Some((sol << sol_zeros, k + sol_zeros))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hensel_solve_zero() {
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(8u32), 3),
            Some((BigUint::zero(), 1))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(32u32), 5),
            Some((BigUint::zero(), 2))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(64u32), 6),
            Some((BigUint::zero(), 2))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(128u32), 7),
            Some((BigUint::zero(), 3))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(16u32), 3),
            Some((BigUint::zero(), 1))
        );
    }

    #[test]
    fn hensel_solve_no_solution() {
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(4u32), 3),
            None
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(2u32), 3),
            None
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(12u32), 3),
            None
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(48u32), 6),
            None
        );
    }

    #[test]
    fn hensel_solve_odd() {
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(7u32), 6),
            Some((BigUint::from(23u32), 6))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(1u32), &BigUint::from(7u32), 6),
            Some((BigUint::from(7u32), 6))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(7u32), &BigUint::from(1u32), 6),
            Some((BigUint::from(1u32), 6))
        );
    }

    #[test]
    fn hensel_solve_even() {
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(8u32), 6),
            Some((BigUint::from(2u32), 4))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(8u32), 10),
            Some((BigUint::from(2u32), 8))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(192u32), 10),
            Some((BigUint::from(44u32), 6))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(3u32), &BigUint::from(216u32), 10),
            Some((BigUint::from(6u32), 8))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(5u32), &BigUint::from(32u32), 10),
            Some((BigUint::from(2u32), 6))
        );
        assert_eq!(
            hensel_solve(&BigUint::from(5u32), &BigUint::from(736u32), 10),
            Some((BigUint::from(46u32), 6))
        );
    }
}
