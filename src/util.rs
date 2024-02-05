#![allow(clippy::let_unit_value)]

#[inline]
pub const fn split_array_ref<T, const N: usize>(slice: &[T]) -> (&[T; N], &[T]) {
    let (a, b) = slice.split_at(N);
    // SAFETY: a points to [T; N]? Yes it's [T] of length N (checked by split_at)
    unsafe { (&*a.as_ptr().cast(), b) }
}

#[inline]
pub fn split_array_mut<T, const N: usize>(slice: &mut [T]) -> (&mut [T; N], &mut [T]) {
    let (a, b) = slice.split_at_mut(N);
    // SAFETY: a points to [T; N]? Yes it's [T] of length N (checked by split_at_mut)
    unsafe { (&mut *a.as_mut_ptr().cast(), b) }
}

#[inline]
pub const fn split_array_exact_ref<T, const M: usize, const N: usize, const K: usize>(
    slice: &[T; M],
) -> (&[T; N], &[T; K]) {
    #![allow(clippy::let_unit_value)]
    let () = AssertSplitExact::<M, N, K>::OK;
    let ptr = slice.as_ptr();
    unsafe { (&*ptr.cast(), &*ptr.add(N).cast()) }
}

#[inline]
pub fn split_array_exact_mut<T, const M: usize, const N: usize, const K: usize>(
    slice: &mut [T; M],
) -> (&mut [T; N], &mut [T; K]) {
    let () = AssertSplitExact::<M, N, K>::OK;
    let ptr = slice.as_mut_ptr();
    unsafe { (&mut *ptr.cast(), &mut *ptr.add(N).cast()) }
}

#[inline]
pub const fn as_chunks_exact<T, const N: usize>(slice: &[T]) -> &[[T; N]] {
    let () = AssertNonZero::<N>::OK;
    let (len, rem_len) = (slice.len() / N, slice.len() % N);
    assert!(rem_len == 0, "chunk size must be an exact multiple of slice len");
    unsafe { core::slice::from_raw_parts(slice.as_ptr().cast(), len) }
}

#[inline]
pub fn as_chunks_exact_mut<T, const N: usize>(slice: &mut [T]) -> &mut [[T; N]] {
    let () = AssertNonZero::<N>::OK;
    let (len, rem_len) = (slice.len() / N, slice.len() % N);
    assert!(rem_len == 0, "chunk size must be an exact multiple of slice len");
    unsafe { core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast(), len) }
}

pub(crate) struct AssertSplitExact<const M: usize, const N: usize, const K: usize>;

impl<const M: usize, const N: usize, const K: usize> AssertSplitExact<M, N, K> {
    pub const OK: () = {
        let (sum, overflow) = N.overflowing_add(K);
        assert!(!overflow && sum == M, "M must be exactly N + K")
    };
}

struct AssertNonZero<const N: usize>;

impl<const N: usize> AssertNonZero<N> {
    const OK: () = assert!(N != 0, "N cannot be 0");
}

pub(crate) struct AssertLess<const N: usize, const M: usize>;

impl<const N: usize, const M: usize> AssertLess<N, M> {
    pub const OK: () = assert!(N < M, "N has to be less than M");
}

pub(crate) struct AssertDivisible<const N: usize, const M: usize>;

impl<const N: usize, const M: usize> AssertDivisible<N, M> {
    pub const OK: () = assert!(N % M == 0, "N has to be divisible by M");
}

macro_rules! assert_unchecked {
    ($cond:expr) => ($crate::util::assert_unchecked!($cond,));
    ($expr:expr, $($arg:tt)*) => ({
        #[cfg(debug_assertions)]
        {
            unsafe fn __needs_unsafe(){}
            __needs_unsafe();
            assert!($expr, $($arg)*);
        }
        #[cfg(not(debug_assertions))]
        {
            if !($expr) { ::core::hint::unreachable_unchecked() }
        }
    })
}

pub(crate) use assert_unchecked;
