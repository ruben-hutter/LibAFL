//! This is a basic SymCC runtime.
//! It traces the execution to the shared memory region that should be passed through the environment by the fuzzer process.
//! Additionally, it concretizes all floating point operations for simplicity.
//! Refer to the `symcc_runtime` crate documentation for building your own runtime.

// The lib needs to be named SymRuntime for SymCC to find it
#![allow(non_snake_case)]

use std::sync::atomic::{AtomicBool, Ordering};

use symcc_runtime::{
    filter::{CallStackCoverage, FilterRuntime, NoFloat},
    tracing, OptionalRuntime, Runtime, RSymExpr, StdShMem,
};

type InnerRuntime = FilterRuntime<
    NoFloat,
    FilterRuntime<CallStackCoverage, OptionalRuntime<tracing::TracingRuntime<StdShMem>>>,
>;

static mut GLOBAL_DATA: Option<InnerRuntime> = None;
static INITIALIZED: AtomicBool = AtomicBool::new(false);

fn with_state<R>(cb: impl FnOnce(&mut InnerRuntime) -> R) -> R {
    if !INITIALIZED.load(Ordering::Acquire) {
        let inner = OptionalRuntime::new(
            tracing::StdShMemMessageFileWriter::from_stdshmem_default_env()
                .ok()
                .map(|writer| tracing::TracingRuntime::new(writer, false)),
        );
        unsafe {
            GLOBAL_DATA = Some(FilterRuntime::new(
                NoFloat,
                FilterRuntime::new(CallStackCoverage::default(), inner),
            ));
        }
        INITIALIZED.store(true, Ordering::Release);
    }
    let s = unsafe { GLOBAL_DATA.as_mut().unwrap() };
    cb(s)
}

// Manual exports matching the _rsym_* interface expected by libSymCCRtShared.so

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_integer(value: u64, bits: u8) -> Option<RSymExpr> {
    with_state(|rt| rt.build_integer(value, bits))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_integer128(high: u64, low: u64) -> Option<RSymExpr> {
    with_state(|rt| rt.build_integer128(high, low))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_integer_from_buffer(
    buffer: *mut std::os::raw::c_void,
    num_bits: std::os::raw::c_uint,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_integer_from_buffer(buffer, num_bits))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float(value: f64, is_double: bool) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float(value, is_double))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_null_pointer() -> Option<RSymExpr> {
    with_state(|rt| rt.build_null_pointer())
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_true() -> Option<RSymExpr> {
    with_state(|rt| rt.build_true())
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_false() -> Option<RSymExpr> {
    with_state(|rt| rt.build_false())
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_bool(value: bool) -> Option<RSymExpr> {
    with_state(|rt| rt.build_bool(value))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_neg(expr: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_neg(expr))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_add(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_add(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_sub(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_sub(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_mul(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_mul(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_unsigned_div(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_unsigned_div(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_signed_div(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_signed_div(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_unsigned_rem(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_unsigned_rem(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_signed_rem(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_signed_rem(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_shift_left(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_shift_left(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_logical_shift_right(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_logical_shift_right(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_arithmetic_shift_right(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_arithmetic_shift_right(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_fp_add(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_fp_add(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_fp_sub(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_fp_sub(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_fp_mul(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_fp_mul(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_fp_div(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_fp_div(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_fp_rem(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_fp_rem(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_fp_abs(expr: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_fp_abs(expr))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_fp_neg(expr: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_fp_neg(expr))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_not(expr: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_not(expr))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_signed_less_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_signed_less_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_signed_less_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_signed_less_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_signed_greater_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_signed_greater_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_signed_greater_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_signed_greater_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_unsigned_less_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_unsigned_less_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_unsigned_less_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_unsigned_less_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_unsigned_greater_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_unsigned_greater_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_unsigned_greater_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_unsigned_greater_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_equal(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_not_equal(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_not_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_bool_and(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_bool_and(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_and(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_and(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_bool_or(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_bool_or(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_or(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_or(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_bool_xor(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_bool_xor(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_xor(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_xor(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_ite(
    cond: RSymExpr,
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_ite(cond, a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_ordered_greater_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_ordered_greater_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_ordered_greater_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_ordered_greater_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_ordered_less_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_ordered_less_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_ordered_less_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_ordered_less_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_ordered_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_ordered_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_ordered_not_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_ordered_not_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_ordered(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_ordered(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_unordered(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_unordered(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_unordered_greater_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_unordered_greater_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_unordered_greater_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_unordered_greater_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_unordered_less_than(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_unordered_less_than(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_unordered_less_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_unordered_less_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_unordered_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_unordered_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_unordered_not_equal(
    a: RSymExpr,
    b: RSymExpr,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_unordered_not_equal(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_sext(expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
    with_state(|rt| rt.build_sext(expr, bits))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_zext(expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
    with_state(|rt| rt.build_zext(expr, bits))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_trunc(expr: RSymExpr, bits: u8) -> Option<RSymExpr> {
    with_state(|rt| rt.build_trunc(expr, bits))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_int_to_float(
    value: RSymExpr,
    is_double: bool,
    is_signed: bool,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_int_to_float(value, is_double, is_signed))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_to_float(
    expr: RSymExpr,
    to_double: bool,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_to_float(expr, to_double))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_bits_to_float(
    expr: RSymExpr,
    to_double: bool,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_bits_to_float(expr, to_double))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_to_bits(expr: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_to_bits(expr))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_to_signed_integer(
    expr: RSymExpr,
    bits: u8,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_to_signed_integer(expr, bits))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_float_to_unsigned_integer(
    expr: RSymExpr,
    bits: u8,
) -> Option<RSymExpr> {
    with_state(|rt| rt.build_float_to_unsigned_integer(expr, bits))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_build_bool_to_bit(expr: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.build_bool_to_bit(expr))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_concat_helper(a: RSymExpr, b: RSymExpr) -> Option<RSymExpr> {
    with_state(|rt| rt.concat_helper(a, b))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_extract_helper(
    expr: RSymExpr,
    first_bit: usize,
    last_bit: usize,
) -> Option<RSymExpr> {
    with_state(|rt| rt.extract_helper(expr, first_bit, last_bit))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_push_path_constraint(
    constraint: Option<RSymExpr>,
    taken: bool,
    site_id: usize,
) {
    if let Some(constraint) = constraint {
        with_state(|rt| rt.push_path_constraint(constraint, taken, site_id))
    }
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_get_input_byte(
    offset: usize,
    value: u8,
) -> Option<RSymExpr> {
    with_state(|rt| rt.get_input_byte(offset, value))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_notify_call(site_id: usize) {
    with_state(|rt| rt.notify_call(site_id))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_notify_ret(site_id: usize) {
    with_state(|rt| rt.notify_ret(site_id))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_notify_basic_block(site_id: usize) {
    with_state(|rt| rt.notify_basic_block(site_id))
}

#[no_mangle]
pub unsafe extern "C" fn _rsym_expression_unreachable(
    expressions: *mut RSymExpr,
    num_elements: usize,
) {
    let slice = std::slice::from_raw_parts(expressions, num_elements);
    with_state(|rt| rt.expression_unreachable(slice))
}

// C++ runtime exports (forwarded from cpp_runtime bindings)
use symcc_runtime::cpp_runtime;

#[no_mangle]
pub unsafe extern "C" fn _sym_initialize() {
    cpp_runtime::_sym_initialize();
}

#[no_mangle]
pub unsafe extern "C" fn _sym_make_symbolic(
    data: *const std::os::raw::c_void,
    byte_length: usize,
    input_offset: usize,
) {
    cpp_runtime::_sym_make_symbolic(data, byte_length, input_offset);
}

#[no_mangle]
pub unsafe extern "C" fn _sym_get_input_byte(offset: usize, concrete_value: u8) -> cpp_runtime::SymExpr {
    cpp_runtime::_sym_get_input_byte(offset, concrete_value)
}

#[no_mangle]
pub unsafe extern "C" fn _sym_push_path_constraint(
    constraint: cpp_runtime::SymExpr,
    taken: std::os::raw::c_int,
    site_id: usize,
) {
    cpp_runtime::_sym_push_path_constraint(constraint, taken, site_id);
}

#[no_mangle]
pub unsafe extern "C" fn _sym_notify_basic_block(site_id: usize) {
    cpp_runtime::_sym_notify_basic_block(site_id);
}

#[no_mangle]
pub unsafe extern "C" fn _sym_notify_call(site_id: usize) {
    cpp_runtime::_sym_notify_call(site_id);
}

#[no_mangle]
pub unsafe extern "C" fn _sym_notify_ret(site_id: usize) {
    cpp_runtime::_sym_notify_ret(site_id);
}

#[no_mangle]
pub unsafe extern "C" fn _sym_build_integer(value: u64, bits: u8) -> cpp_runtime::SymExpr {
    cpp_runtime::_sym_build_integer(value, bits)
}

#[no_mangle]
pub unsafe extern "C" fn _sym_build_null_pointer() -> cpp_runtime::SymExpr {
    cpp_runtime::_sym_build_null_pointer()
}

#[no_mangle]
pub unsafe extern "C" fn _sym_build_true() -> cpp_runtime::SymExpr {
    cpp_runtime::_sym_build_true()
}

#[no_mangle]
pub unsafe extern "C" fn _sym_build_false() -> cpp_runtime::SymExpr {
    cpp_runtime::_sym_build_false()
}

#[no_mangle]
pub unsafe extern "C" fn _sym_collect_garbage() {
    cpp_runtime::_sym_collect_garbage();
}

#[no_mangle]
pub unsafe extern "C" fn _sym_read_memory(addr: *mut u8, length: usize, little_endian: bool) -> cpp_runtime::SymExpr {
    cpp_runtime::_sym_read_memory(addr, length, little_endian)
}

#[no_mangle]
pub unsafe extern "C" fn _sym_write_memory(addr: *mut u8, length: usize, expr: cpp_runtime::SymExpr, little_endian: bool) {
    cpp_runtime::_sym_write_memory(addr, length, expr, little_endian);
}
