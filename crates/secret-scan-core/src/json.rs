//! A small, strict JSON reader for `runtime-config/v1` (issue #1251), with no
//! dependency.
//!
//! The parser is deliberately narrower than JSON at large: it rejects a
//! duplicate member, nesting beyond [`MAX_DEPTH`], a byte-order mark and any
//! text after the value, and it never reports the offending text, only that
//! the document is malformed. Nothing here writes JSON: the configuration
//! documents are rendered by `crate::config` from fixed words and validated
//! identifiers.

/// The deepest nesting the parser accepts.
const MAX_DEPTH: usize = 8;

/// A JSON value. Numbers are non-negative integers or [`Value::Other`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    /// A non-negative integer that fits `u64`.
    Int(u64),
    /// Any other number: negative, fractional, with an exponent, or too large.
    Other,
    Str(String),
    Array(Vec<Value>),
    /// Members in document order; the parser rejects a repeated name.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member named `name`, when this is an object that has one.
    pub(crate) fn member(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(member, _)| member == name)
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

/// Parses `text` as one JSON value, or `None` when it is malformed.
pub(crate) fn parse(text: &str) -> Option<Value> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        at: 0,
    };
    let value = parser.value(0)?;
    parser.skip_whitespace();
    (parser.at == parser.bytes.len()).then_some(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn skip_whitespace(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Option<Value> {
        if self.bytes[self.at..].starts_with(word) {
            self.at += word.len();
            Some(value)
        } else {
            None
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.skip_whitespace();
        match self.peek()? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Value::Str),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        let digits = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        if self.at == digits {
            return None;
        }
        let integer = &self.bytes[digits..self.at];
        let leading_zero = integer.len() > 1 && integer[0] == b'0';
        let mut plain = self.bytes[start] != b'-';
        if self.peek() == Some(b'.') {
            plain = false;
            self.at += 1;
            let fraction = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == fraction {
                return None;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            plain = false;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            let exponent = self.at;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.at += 1;
            }
            if self.at == exponent {
                return None;
            }
        }
        if leading_zero {
            return None;
        }
        if !plain {
            return Some(Value::Other);
        }
        std::str::from_utf8(integer)
            .ok()
            .and_then(|digits| digits.parse::<u64>().ok())
            .map_or(Some(Value::Other), |value| Some(Value::Int(value)))
    }

    fn string(&mut self) -> Option<String> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let start = self.at;
            while self
                .peek()
                .is_some_and(|byte| byte != b'"' && byte != b'\\' && byte >= 0x20)
            {
                self.at += 1;
            }
            out.push_str(std::str::from_utf8(&self.bytes[start..self.at]).ok()?);
            match self.peek()? {
                b'"' => {
                    self.at += 1;
                    return Some(out);
                }
                b'\\' => {
                    self.at += 1;
                    let escape = self.peek()?;
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let digits = self.bytes.get(self.at..self.at + 4)?;
                            let code =
                                u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()?;
                            self.at += 4;
                            // A lone surrogate is kept as U+FFFD: no value
                            // that reaches here is ever a valid identifier.
                            out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                        }
                        _ => return None,
                    }
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        self.at += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek()? == b']' {
            self.at += 1;
            return Some(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek()? {
                b',' => self.at += 1,
                b']' => {
                    self.at += 1;
                    return Some(Value::Array(items));
                }
                _ => return None,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        self.at += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.skip_whitespace();
        if self.peek()? == b'}' {
            self.at += 1;
            return Some(Value::Object(members));
        }
        loop {
            self.skip_whitespace();
            if self.peek()? != b'"' {
                return None;
            }
            let name = self.string()?;
            if members.iter().any(|(existing, _)| *existing == name) {
                return None;
            }
            self.skip_whitespace();
            if self.peek()? != b':' {
                return None;
            }
            self.at += 1;
            members.push((name, self.value(depth + 1)?));
            self.skip_whitespace();
            match self.peek()? {
                b',' => self.at += 1,
                b'}' => {
                    self.at += 1;
                    return Some(Value::Object(members));
                }
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_value_kinds_and_keeps_member_order() {
        let value = parse(r#" {"b":[1,"x",true,null],"a":{"c":0}} "#).expect("parses");
        let Value::Object(members) = &value else {
            unreachable!("the document is an object")
        };
        assert_eq!(members[0].0, "b");
        assert_eq!(members[1].0, "a");
        assert_eq!(
            value.member("a").and_then(|a| a.member("c")),
            Some(&Value::Int(0))
        );
        assert_eq!(value.member("missing"), None);
    }

    #[test]
    fn rejects_malformed_text_without_reporting_it() {
        for bad in [
            "",
            "{",
            "}",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\":1 \"b\":2}",
            "{\"a\":1}x",
            "01",
            "1.",
            "-",
            "\"\\x\"",
            "\"a\nb\"",
            "{\"a\":1,\"a\":2}",
            "\u{feff}{}",
            "tru",
            "{1:2}",
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
        let deep = format!(
            "{}1{}",
            "[".repeat(MAX_DEPTH + 2),
            "]".repeat(MAX_DEPTH + 2)
        );
        assert!(parse(&deep).is_none());
        let ok = format!("{}1{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_some());
    }

    #[test]
    fn numbers_are_non_negative_integers_or_other() {
        assert_eq!(parse("7"), Some(Value::Int(7)));
        assert_eq!(parse("18446744073709551615"), Some(Value::Int(u64::MAX)));
        for other in ["-1", "1.5", "1e3", "18446744073709551616"] {
            assert_eq!(parse(other), Some(Value::Other), "{other}");
        }
    }

    #[test]
    fn escapes_decode_and_a_lone_surrogate_never_becomes_an_identifier() {
        assert_eq!(parse(r#""a\u0062\n""#), Some(Value::Str("ab\n".to_owned())));
        assert_eq!(
            parse(r#""\ud800""#),
            Some(Value::Str("\u{fffd}".to_owned()))
        );
    }
}
