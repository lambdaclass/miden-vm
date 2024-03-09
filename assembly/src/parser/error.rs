use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, ops::Range};

use super::{ParseError, SourceSpan};
use crate::diagnostics::Diagnostic;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LiteralErrorKind {
    /// The input was empty
    Empty,
    /// The input contained an invalid digit
    InvalidDigit,
    /// The value overflows `u32::MAX`
    U32Overflow,
    /// The value overflows `Felt::MODULUS`
    FeltOverflow,
    /// The value was expected to be a value < 63
    InvalidBitSize,
}
impl fmt::Display for LiteralErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("input was empty"),
            Self::InvalidDigit => f.write_str("invalid digit"),
            Self::U32Overflow => f.write_str("value overflowed the u32 range"),
            Self::FeltOverflow => f.write_str("value overflowed the field modulus"),
            Self::InvalidBitSize => {
                f.write_str("expected value to be a valid bit size, e.g. 0..63")
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HexErrorKind {
    /// Expected two hex digits for every byte, but had fewer than that
    MissingDigits,
    /// Valid hex-encoded integers are expected to come in sizes of 8, 16, or 64 digits,
    /// but the input consisted of an invalid number of digits.
    Invalid,
    /// Occurs when a hex-encoded value overflows `Felt::MODULUS`, the maximum integral value
    Overflow,
    /// Occurs when the hex-encoded value is > 64 digits
    TooLong,
}
impl fmt::Display for HexErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingDigits => {
                f.write_str("expected number of hex digits to be a multiple of 2")
            }
            Self::Invalid => f.write_str("expected 2, 4, 8, 16, or 64 hex digits"),
            Self::Overflow => f.write_str("value overflowed the field modulus"),
            Self::TooLong => f.write_str(
                "value has too many digits, long hex strings must contain exactly 64 digits",
            ),
        }
    }
}

#[derive(Debug, Default, Clone, thiserror::Error, Diagnostic)]
#[repr(u8)]
pub enum ParsingError {
    #[default]
    #[error("parsing failed due to unexpected input")]
    #[diagnostic()]
    Failed = 0,
    #[error("invalid token")]
    #[diagnostic()]
    InvalidToken {
        #[label("occurs here")]
        span: SourceSpan,
    },
    #[error("unrecognized token")]
    #[diagnostic(help("expected {}", expected.as_slice().join(", or ")))]
    UnrecognizedToken {
        #[label("lexed a {token} here")]
        span: SourceSpan,
        token: String,
        expected: Vec<String>,
    },
    #[error("unexpected trailing tokens")]
    #[diagnostic()]
    ExtraToken {
        #[label("{token} was found here, but was not expected")]
        span: SourceSpan,
        token: String,
    },
    #[error("unexpected end of file")]
    #[diagnostic(help("expected {}", expected.as_slice().join(", or ")))]
    UnrecognizedEof {
        #[label("reached end of file here")]
        span: SourceSpan,
        expected: Vec<String>,
    },
    #[error("invalid character in identifier")]
    #[diagnostic(help("bare identifiers must be lowercase alphanumeric with '_', quoted identifiers can include uppercase, as well as '.' and '$'"))]
    InvalidIdentCharacter {
        #[label]
        span: SourceSpan,
    },
    #[error("unclosed quoted identifier")]
    #[diagnostic()]
    UnclosedQuote {
        #[label("no match for quotation mark starting here")]
        start: SourceSpan,
    },
    #[error("too many instructions in a single code block")]
    #[diagnostic()]
    CodeBlockTooBig {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid constant expression: division by zero")]
    DivisionByZero {
        #[label]
        span: SourceSpan,
    },
    #[error("doc comment is too large")]
    #[diagnostic(help("make sure it is less than u16::MAX bytes in length"))]
    DocsTooLarge {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid literal: {}", kind)]
    #[diagnostic()]
    InvalidLiteral {
        #[label]
        span: SourceSpan,
        kind: LiteralErrorKind,
    },
    #[error("invalid literal: {}", kind)]
    #[diagnostic()]
    InvalidHexLiteral {
        #[label]
        span: SourceSpan,
        kind: HexErrorKind,
    },
    #[error("invalid MAST root literal")]
    InvalidMastRoot {
        #[label]
        span: SourceSpan,
    },
    #[error("invalid library path: {}", message)]
    InvalidLibraryPath {
        #[label]
        span: SourceSpan,
        message: String,
    },
    #[error("invalid immediate: value must be in the range {}..{} (exclusive)", range.start, range.end)]
    ImmediateOutOfRange {
        #[label]
        span: SourceSpan,
        range: Range<usize>,
    },
    #[error("too many procedures in this module")]
    #[diagnostic()]
    ModuleTooLarge {
        #[label]
        span: SourceSpan,
    },
    #[error("too many re-exported procedures in this module")]
    #[diagnostic()]
    ModuleTooManyReexports {
        #[label]
        span: SourceSpan,
    },
    #[error("too many operands for `push`: tried to push {} elements, but only 16 can be pushed at one time", count)]
    #[diagnostic()]
    PushOverflow {
        #[label]
        span: SourceSpan,
        count: usize,
    },
    #[error("unclosed quoted identifier")]
    #[diagnostic(help(
        "parsing reached the end of the line before seeing a closing double-quote"
    ))]
    UnclosedQuotedIdentifier {
        #[label]
        span: SourceSpan,
    },
    #[error("expected a fully-qualified module path, e.g. `std::u64`")]
    UnqualifiedImport {
        #[label]
        span: SourceSpan,
    },
}
impl ParsingError {
    fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        unsafe { *<*const _>::from(self).cast::<u8>() }
    }
}
impl Eq for ParsingError {}
impl PartialEq for ParsingError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Failed, Self::Failed) => true,
            (Self::InvalidLiteral { kind: l, .. }, Self::InvalidLiteral { kind: r, .. }) => l == r,
            (Self::InvalidHexLiteral { kind: l, .. }, Self::InvalidHexLiteral { kind: r, .. }) => {
                l == r
            }
            (
                Self::InvalidLibraryPath { message: l, .. },
                Self::InvalidLibraryPath { message: r, .. },
            ) => l == r,
            (
                Self::ImmediateOutOfRange { range: l, .. },
                Self::ImmediateOutOfRange { range: r, .. },
            ) => l == r,
            (Self::PushOverflow { count: l, .. }, Self::PushOverflow { count: r, .. }) => l == r,
            (
                Self::UnrecognizedToken {
                    token: ltok,
                    expected: lexpect,
                    ..
                },
                Self::UnrecognizedToken {
                    token: rtok,
                    expected: rexpect,
                    ..
                },
            ) => ltok == rtok && lexpect == rexpect,
            (Self::ExtraToken { token: ltok, .. }, Self::ExtraToken { token: rtok, .. }) => {
                ltok == rtok
            }
            (
                Self::UnrecognizedEof {
                    expected: lexpect, ..
                },
                Self::UnrecognizedEof {
                    expected: rexpect, ..
                },
            ) => lexpect == rexpect,
            (x, y) => x.tag() == y.tag(),
        }
    }
}

pub fn handle_parse_error(err: ParseError) -> ParsingError {
    use super::Token;
    match err {
        ParseError::InvalidToken { location: at } => ParsingError::InvalidToken {
            span: SourceSpan::from(at..at),
        },
        ParseError::UnrecognizedToken {
            token: (l, Token::Eof, r),
            expected,
        } => ParsingError::UnrecognizedEof {
            span: SourceSpan::from(l..r),
            expected: simplify_expected_tokens(expected),
        },
        ParseError::UnrecognizedToken {
            token: (l, tok, r),
            expected,
        } => ParsingError::UnrecognizedToken {
            span: SourceSpan::from(l..r),
            token: tok.to_string(),
            expected: simplify_expected_tokens(expected),
        },
        ParseError::ExtraToken { token: (l, tok, r) } => ParsingError::ExtraToken {
            span: SourceSpan::from(l..r),
            token: tok.to_string(),
        },
        ParseError::UnrecognizedEof {
            location: at,
            expected,
        } => ParsingError::UnrecognizedEof {
            span: SourceSpan::from(at..at),
            expected: simplify_expected_tokens(expected),
        },
        ParseError::User { error } => error,
    }
}

// The parser generator will show every token that is expected
// in some scenarios, so to avoid cluttering the diagnostic output
// with all of the instruction opcodes, we collapse them into a
// single token
fn simplify_expected_tokens(expected: Vec<String>) -> Vec<String> {
    use super::Token;
    let mut has_instruction = false;
    let mut has_ctrl = false;
    expected
        .into_iter()
        .filter_map(|t| {
            let tok = match t.as_str() {
                "bare_ident" => return Some("identifier".to_string()),
                "const_ident" => return Some("constant identifier".to_string()),
                "quoted_ident" => return Some("quoted identifier".to_string()),
                "doc_comment" => return Some("doc comment".to_string()),
                "hex_value" => return Some("hex-encoded literal".to_string()),
                "uint" => return Some("integer literal".to_string()),
                "EOF" => return Some("end of file".to_string()),
                other => other[1..].strip_suffix('"').and_then(|t| Token::parse(t).ok()),
            };
            match tok {
                Some(Token::If | Token::While | Token::Repeat) => {
                    if !has_ctrl {
                        has_ctrl = true;
                        Some("control flow opcode (e.g. \"if.true\")".to_string())
                    } else {
                        None
                    }
                }
                Some(tok) if tok.is_instruction() => {
                    if !has_instruction {
                        has_instruction = true;
                        Some("primtive opcode (e.g. \"add\")".to_string())
                    } else {
                        None
                    }
                }
                _ => Some(t),
            }
        })
        .collect()
}