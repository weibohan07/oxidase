#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_core::{EvalContext, Expression};

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data)
        && let Ok(expression) = Expression::compile(source)
    {
        let _ = expression.evaluate(&EvalContext::default());
    }
});
