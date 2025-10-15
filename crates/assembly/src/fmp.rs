use alloc::vec::Vec;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, Operation};

/// Returns the sequence of operations that initialize the frame pointer in memory.
///
/// This must be called at the beginning of a new execution context, i.e. at the start of the
/// program, and after a `CALL` or `DYNCALL` instruction.
pub(crate) fn fmp_initialization_sequence() -> Vec<Operation> {
    vec![
        Operation::Push(FMP_INIT_VALUE),
        Operation::Push(FMP_ADDR),
        Operation::MStore,
        Operation::Drop,
    ]
}
