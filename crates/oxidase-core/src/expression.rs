use std::cmp::Ordering;
use std::collections::BTreeMap;

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use thiserror::Error;

use crate::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    Field(String),
    Index(usize),
}

#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    roots: BTreeMap<String, Value>,
}

impl EvalContext {
    #[must_use]
    pub fn new(roots: BTreeMap<String, Value>) -> Self {
        Self { roots }
    }

    pub fn insert(&mut self, name: impl Into<String>, value: Value) -> Option<Value> {
        self.roots.insert(name.into(), value)
    }

    #[must_use]
    pub fn root(&self, name: &str) -> Option<&Value> {
        self.roots.get(name)
    }
}

#[derive(Debug, Clone)]
pub struct Expression {
    source: String,
    root: Expr,
}

impl Expression {
    pub fn compile(source: impl Into<String>) -> Result<Self, ExpressionError> {
        let source = source.into();
        let mut parser = Parser::new(&source)?;
        let root = parser.parse_expression()?;
        parser.expect(Token::End)?;
        Ok(Self { source, root })
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn evaluate(&self, context: &EvalContext) -> Result<Value, ExpressionError> {
        self.root.evaluate(context)
    }
}

#[derive(Debug, Clone)]
enum Expr {
    Literal(Value),
    Root(String),
    Index(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Binary {
        operator: BinaryOperator,
        left: Box<Self>,
        right: Box<Self>,
    },
    Call {
        name: String,
        arguments: Vec<Self>,
    },
}

impl Expr {
    fn evaluate(&self, context: &EvalContext) -> Result<Value, ExpressionError> {
        match self {
            Self::Literal(value) => Ok(value.clone()),
            Self::Root(name) => Ok(context.root(name).cloned().unwrap_or(Value::Null)),
            Self::Index(value, index) => {
                let value = value.evaluate(context)?;
                let index = index.evaluate(context)?;
                match (&value, index) {
                    (Value::Map(values), Value::String(key)) => {
                        Ok(values.get(&key).cloned().unwrap_or(Value::Null))
                    }
                    (Value::List(values), Value::Integer(index)) if index >= 0 => {
                        Ok(values.get(index as usize).cloned().unwrap_or(Value::Null))
                    }
                    (Value::Null, _) => Ok(Value::Null),
                    (value, index) => Err(ExpressionError::Evaluation(format!(
                        "cannot index {} with {}",
                        value.type_name(),
                        index.type_name()
                    ))),
                }
            }
            Self::Not(value) => Ok(Value::Bool(!require_bool(value.evaluate(context)?)?)),
            Self::Binary {
                operator,
                left,
                right,
            } => operator.evaluate(left, right, context),
            Self::Call { name, arguments } => {
                let values = arguments
                    .iter()
                    .map(|argument| argument.evaluate(context))
                    .collect::<Result<Vec<_>, _>>()?;
                evaluate_function(name, &values)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BinaryOperator {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    And,
    Or,
    In,
    Coalesce,
}

impl BinaryOperator {
    fn evaluate(
        self,
        left: &Expr,
        right: &Expr,
        context: &EvalContext,
    ) -> Result<Value, ExpressionError> {
        match self {
            Self::And => {
                let left = require_bool(left.evaluate(context)?)?;
                if !left {
                    return Ok(Value::Bool(false));
                }
                Ok(Value::Bool(require_bool(right.evaluate(context)?)?))
            }
            Self::Or => {
                let left = require_bool(left.evaluate(context)?)?;
                if left {
                    return Ok(Value::Bool(true));
                }
                Ok(Value::Bool(require_bool(right.evaluate(context)?)?))
            }
            Self::Coalesce => {
                let left = left.evaluate(context)?;
                if left.is_null() {
                    right.evaluate(context)
                } else {
                    Ok(left)
                }
            }
            operator => {
                let left = left.evaluate(context)?;
                let right = right.evaluate(context)?;
                match operator {
                    Self::Equal => Ok(Value::Bool(left == right)),
                    Self::NotEqual => Ok(Value::Bool(left != right)),
                    Self::Less => compare(&left, &right, |value| value == Ordering::Less),
                    Self::LessEqual => compare(&left, &right, |value| value != Ordering::Greater),
                    Self::Greater => compare(&left, &right, |value| value == Ordering::Greater),
                    Self::GreaterEqual => compare(&left, &right, |value| value != Ordering::Less),
                    Self::In => evaluate_in(&left, &right),
                    Self::And | Self::Or | Self::Coalesce => unreachable!("handled above"),
                }
            }
        }
    }
}

fn require_bool(value: Value) -> Result<bool, ExpressionError> {
    value.as_bool().ok_or_else(|| {
        ExpressionError::Evaluation(format!("expected bool, received {}", value.type_name()))
    })
}

fn compare(
    left: &Value,
    right: &Value,
    predicate: impl FnOnce(Ordering) -> bool,
) -> Result<Value, ExpressionError> {
    let ordering = match (left, right) {
        (Value::Integer(left), Value::Integer(right)) => left.partial_cmp(right),
        (Value::Float(left), Value::Float(right)) => left.partial_cmp(right),
        (Value::Integer(left), Value::Float(right)) => (*left as f64).partial_cmp(right),
        (Value::Float(left), Value::Integer(right)) => left.partial_cmp(&(*right as f64)),
        (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
        _ => None,
    }
    .ok_or_else(|| {
        ExpressionError::Evaluation(format!(
            "values of type {} and {} are not ordered",
            left.type_name(),
            right.type_name()
        ))
    })?;
    Ok(Value::Bool(predicate(ordering)))
}

fn evaluate_in(needle: &Value, haystack: &Value) -> Result<Value, ExpressionError> {
    let contains = match haystack {
        Value::List(values) => values.contains(needle),
        Value::Map(values) => needle
            .as_str()
            .is_some_and(|needle| values.contains_key(needle)),
        Value::String(value) => needle.as_str().is_some_and(|needle| value.contains(needle)),
        _ => {
            return Err(ExpressionError::Evaluation(format!(
                "operator `in` does not accept {} on the right",
                haystack.type_name()
            )));
        }
    };
    Ok(Value::Bool(contains))
}

fn evaluate_function(name: &str, arguments: &[Value]) -> Result<Value, ExpressionError> {
    match (name, arguments) {
        ("default", [value, fallback]) => {
            if value.is_null() || value.as_str() == Some("") {
                Ok(fallback.clone())
            } else {
                Ok(value.clone())
            }
        }
        ("lower", [Value::String(value)]) => Ok(Value::String(value.to_lowercase())),
        ("upper", [Value::String(value)]) => Ok(Value::String(value.to_uppercase())),
        ("trim", [Value::String(value)]) => Ok(Value::String(value.trim().to_owned())),
        ("replace", [Value::String(value), Value::String(from), Value::String(to)]) => {
            Ok(Value::String(value.replace(from, to)))
        }
        ("url_encode", [Value::String(value)]) => Ok(Value::String(
            utf8_percent_encode(value, NON_ALPHANUMERIC).to_string(),
        )),
        ("html_escape", [Value::String(value)]) => Ok(Value::String(html_escape(value))),
        ("json_encode", [value]) => serde_json::to_string(value)
            .map(Value::String)
            .map_err(|error| ExpressionError::Evaluation(error.to_string())),
        ("length", [Value::String(value)]) => Ok(Value::Integer(value.chars().count() as i64)),
        ("length", [Value::Bytes(value)]) => Ok(Value::Integer(value.len() as i64)),
        ("length", [Value::List(value)]) => Ok(Value::Integer(value.len() as i64)),
        ("length", [Value::Map(value)]) => Ok(Value::Integer(value.len() as i64)),
        ("join", [Value::List(values), Value::String(separator)]) => values
            .iter()
            .map(Value::render)
            .collect::<Result<Vec<_>, _>>()
            .map(|values| Value::String(values.join(separator)))
            .map_err(|error| ExpressionError::Evaluation(error.to_owned())),
        _ => Err(ExpressionError::Evaluation(format!(
            "unknown function or invalid arguments for `{name}`"
        ))),
    }
}

#[must_use]
pub fn html_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            _ => output.push(character),
        }
    }
    output
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum ExpressionError {
    #[error("expression syntax error at byte {offset}: {message}")]
    Syntax { offset: usize, message: String },
    #[error("expression evaluation failed: {0}")]
    Evaluation(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Identifier(String),
    String(String),
    Integer(i64),
    Float(f64),
    True,
    False,
    Null,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    Dot,
    Comma,
    Pipe,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Coalesce,
    And,
    Or,
    Not,
    In,
    End,
}

struct Parser {
    tokens: Vec<(Token, usize)>,
    position: usize,
}

impl Parser {
    fn new(source: &str) -> Result<Self, ExpressionError> {
        Ok(Self {
            tokens: tokenize(source)?,
            position: 0,
        })
    }

    fn parse_expression(&mut self) -> Result<Expr, ExpressionError> {
        let mut expression = self.parse_coalesce()?;
        while self.take(&Token::Pipe) {
            let name = self.take_identifier()?;
            let mut arguments = vec![expression];
            if self.take(&Token::LeftParen) {
                if !self.check(&Token::RightParen) {
                    loop {
                        arguments.push(self.parse_coalesce()?);
                        if !self.take(&Token::Comma) {
                            break;
                        }
                    }
                }
                self.expect(Token::RightParen)?;
            }
            expression = Expr::Call { name, arguments };
        }
        Ok(expression)
    }

    fn parse_coalesce(&mut self) -> Result<Expr, ExpressionError> {
        let left = self.parse_or()?;
        if self.take(&Token::Coalesce) {
            Ok(Expr::Binary {
                operator: BinaryOperator::Coalesce,
                left: Box::new(left),
                right: Box::new(self.parse_coalesce()?),
            })
        } else {
            Ok(left)
        }
    }

    fn parse_or(&mut self) -> Result<Expr, ExpressionError> {
        let mut expression = self.parse_and()?;
        while self.take(&Token::Or) {
            expression = Expr::Binary {
                operator: BinaryOperator::Or,
                left: Box::new(expression),
                right: Box::new(self.parse_and()?),
            };
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<Expr, ExpressionError> {
        let mut expression = self.parse_comparison()?;
        while self.take(&Token::And) {
            expression = Expr::Binary {
                operator: BinaryOperator::And,
                left: Box::new(expression),
                right: Box::new(self.parse_comparison()?),
            };
        }
        Ok(expression)
    }

    fn parse_comparison(&mut self) -> Result<Expr, ExpressionError> {
        let mut expression = self.parse_unary()?;
        loop {
            let operator = if self.take(&Token::Equal) {
                Some(BinaryOperator::Equal)
            } else if self.take(&Token::NotEqual) {
                Some(BinaryOperator::NotEqual)
            } else if self.take(&Token::LessEqual) {
                Some(BinaryOperator::LessEqual)
            } else if self.take(&Token::Less) {
                Some(BinaryOperator::Less)
            } else if self.take(&Token::GreaterEqual) {
                Some(BinaryOperator::GreaterEqual)
            } else if self.take(&Token::Greater) {
                Some(BinaryOperator::Greater)
            } else if self.take(&Token::In) {
                Some(BinaryOperator::In)
            } else {
                None
            };
            let Some(operator) = operator else {
                break;
            };
            expression = Expr::Binary {
                operator,
                left: Box::new(expression),
                right: Box::new(self.parse_unary()?),
            };
        }
        Ok(expression)
    }

    fn parse_unary(&mut self) -> Result<Expr, ExpressionError> {
        if self.take(&Token::Not) {
            Ok(Expr::Not(Box::new(self.parse_unary()?)))
        } else {
            self.parse_postfix()
        }
    }

    fn parse_postfix(&mut self) -> Result<Expr, ExpressionError> {
        let mut expression = self.parse_primary()?;
        loop {
            if self.take(&Token::Dot) {
                let field = self.take_identifier()?;
                expression = Expr::Index(
                    Box::new(expression),
                    Box::new(Expr::Literal(Value::String(field))),
                );
            } else if self.take(&Token::LeftBracket) {
                let index = self.parse_coalesce()?;
                self.expect(Token::RightBracket)?;
                expression = Expr::Index(Box::new(expression), Box::new(index));
            } else {
                break;
            }
        }
        Ok(expression)
    }

    fn parse_primary(&mut self) -> Result<Expr, ExpressionError> {
        let (token, offset) = self.current().clone();
        self.position += 1;
        match token {
            Token::String(value) => Ok(Expr::Literal(Value::String(value))),
            Token::Integer(value) => Ok(Expr::Literal(Value::Integer(value))),
            Token::Float(value) => Ok(Expr::Literal(Value::Float(value))),
            Token::True => Ok(Expr::Literal(Value::Bool(true))),
            Token::False => Ok(Expr::Literal(Value::Bool(false))),
            Token::Null => Ok(Expr::Literal(Value::Null)),
            Token::Identifier(name) if self.take(&Token::LeftParen) => {
                let mut arguments = Vec::new();
                if !self.check(&Token::RightParen) {
                    loop {
                        arguments.push(self.parse_coalesce()?);
                        if !self.take(&Token::Comma) {
                            break;
                        }
                    }
                }
                self.expect(Token::RightParen)?;
                Ok(Expr::Call { name, arguments })
            }
            Token::Identifier(name) => Ok(Expr::Root(name)),
            Token::LeftParen => {
                let value = self.parse_expression()?;
                self.expect(Token::RightParen)?;
                Ok(value)
            }
            _ => Err(ExpressionError::Syntax {
                offset,
                message: format!("expected a value, found {token:?}"),
            }),
        }
    }

    fn take_identifier(&mut self) -> Result<String, ExpressionError> {
        let (token, offset) = self.current().clone();
        if let Token::Identifier(value) = token {
            self.position += 1;
            Ok(value)
        } else {
            Err(ExpressionError::Syntax {
                offset,
                message: "expected identifier".to_owned(),
            })
        }
    }

    fn current(&self) -> &(Token, usize) {
        &self.tokens[self.position]
    }

    fn check(&self, expected: &Token) -> bool {
        std::mem::discriminant(&self.current().0) == std::mem::discriminant(expected)
    }

    fn take(&mut self, expected: &Token) -> bool {
        if self.check(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: Token) -> Result<(), ExpressionError> {
        if self.take(&expected) {
            Ok(())
        } else {
            Err(ExpressionError::Syntax {
                offset: self.current().1,
                message: format!("expected {expected:?}, found {:?}", self.current().0),
            })
        }
    }
}

fn tokenize(source: &str) -> Result<Vec<(Token, usize)>, ExpressionError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        let byte = bytes[position];
        if byte.is_ascii_whitespace() {
            position += 1;
            continue;
        }
        let offset = position;
        let token = match byte {
            b'(' => single(&mut position, Token::LeftParen),
            b')' => single(&mut position, Token::RightParen),
            b'[' => single(&mut position, Token::LeftBracket),
            b']' => single(&mut position, Token::RightBracket),
            b'.' => single(&mut position, Token::Dot),
            b',' => single(&mut position, Token::Comma),
            b'|' => single(&mut position, Token::Pipe),
            b'=' if bytes.get(position + 1) == Some(&b'=') => {
                position += 2;
                Token::Equal
            }
            b'!' if bytes.get(position + 1) == Some(&b'=') => {
                position += 2;
                Token::NotEqual
            }
            b'<' if bytes.get(position + 1) == Some(&b'=') => {
                position += 2;
                Token::LessEqual
            }
            b'<' => single(&mut position, Token::Less),
            b'>' if bytes.get(position + 1) == Some(&b'=') => {
                position += 2;
                Token::GreaterEqual
            }
            b'>' => single(&mut position, Token::Greater),
            b'?' if bytes.get(position + 1) == Some(&b'?') => {
                position += 2;
                Token::Coalesce
            }
            b'\'' | b'"' => read_string(source, &mut position)?,
            b'-' | b'0'..=b'9' => read_number(source, &mut position)?,
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => read_identifier(source, &mut position),
            _ => {
                return Err(ExpressionError::Syntax {
                    offset,
                    message: format!("unexpected character `{}`", byte as char),
                });
            }
        };
        tokens.push((token, offset));
    }
    tokens.push((Token::End, source.len()));
    Ok(tokens)
}

fn single(position: &mut usize, token: Token) -> Token {
    *position += 1;
    token
}

fn read_identifier(source: &str, position: &mut usize) -> Token {
    let start = *position;
    let bytes = source.as_bytes();
    *position += 1;
    while bytes
        .get(*position)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    {
        *position += 1;
    }
    match &source[start..*position] {
        "true" => Token::True,
        "false" => Token::False,
        "null" => Token::Null,
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "in" => Token::In,
        value => Token::Identifier(value.to_owned()),
    }
}

fn read_number(source: &str, position: &mut usize) -> Result<Token, ExpressionError> {
    let start = *position;
    let bytes = source.as_bytes();
    if bytes[*position] == b'-' {
        *position += 1;
    }
    while bytes.get(*position).is_some_and(u8::is_ascii_digit) {
        *position += 1;
    }
    let is_float = bytes.get(*position) == Some(&b'.');
    if is_float {
        *position += 1;
        while bytes.get(*position).is_some_and(u8::is_ascii_digit) {
            *position += 1;
        }
    }
    let value = &source[start..*position];
    if is_float {
        value
            .parse::<f64>()
            .map(Token::Float)
            .map_err(|_| ExpressionError::Syntax {
                offset: start,
                message: format!("invalid float `{value}`"),
            })
    } else {
        value
            .parse::<i64>()
            .map(Token::Integer)
            .map_err(|_| ExpressionError::Syntax {
                offset: start,
                message: format!("invalid integer `{value}`"),
            })
    }
}

fn read_string(source: &str, position: &mut usize) -> Result<Token, ExpressionError> {
    let start = *position;
    let quote = source.as_bytes()[*position];
    *position += 1;
    let mut output = String::new();
    let bytes = source.as_bytes();
    while let Some(byte) = bytes.get(*position).copied() {
        *position += 1;
        if byte == quote {
            return Ok(Token::String(output));
        }
        if byte == b'\\' {
            let escaped = bytes
                .get(*position)
                .copied()
                .ok_or_else(|| ExpressionError::Syntax {
                    offset: start,
                    message: "unclosed string literal".to_owned(),
                })?;
            *position += 1;
            output.push(match escaped {
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'\\' => '\\',
                b'\'' => '\'',
                b'"' => '"',
                _ => {
                    return Err(ExpressionError::Syntax {
                        offset: *position - 1,
                        message: "unsupported string escape".to_owned(),
                    });
                }
            });
        } else if byte.is_ascii() {
            output.push(byte as char);
        } else {
            let rest = &source[*position - 1..];
            let character = rest.chars().next().ok_or_else(|| ExpressionError::Syntax {
                offset: *position - 1,
                message: "invalid UTF-8 string".to_owned(),
            })?;
            output.push(character);
            *position += character.len_utf8() - 1;
        }
    }
    Err(ExpressionError::Syntax {
        offset: start,
        message: "unclosed string literal".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{EvalContext, Expression};
    use crate::Value;

    fn context() -> EvalContext {
        let mut bindings = BTreeMap::new();
        bindings.insert("user".to_owned(), Value::from(" Alice "));
        bindings.insert("count".to_owned(), Value::Integer(3));
        let mut roots = BTreeMap::new();
        roots.insert("bindings".to_owned(), Value::Map(bindings));
        EvalContext::new(roots)
    }

    #[test]
    fn evaluates_access_comparison_and_boolean_operators() {
        let expression = Expression::compile("bindings.count >= 3 and bindings.user != null")
            .expect("valid expression");
        assert_eq!(
            expression
                .evaluate(&context())
                .expect("expression evaluates"),
            Value::Bool(true)
        );
    }

    #[test]
    fn evaluates_coalesce_and_filter_chain() {
        let expression = Expression::compile("(bindings.missing ?? bindings.user) | trim | lower")
            .expect("valid expression");
        assert_eq!(
            expression
                .evaluate(&context())
                .expect("expression evaluates"),
            Value::from("alice")
        );
    }

    #[test]
    fn preserves_structured_values() {
        let expression = Expression::compile("bindings.count").expect("valid expression");
        assert_eq!(
            expression
                .evaluate(&context())
                .expect("expression evaluates"),
            Value::Integer(3)
        );
    }

    #[test]
    fn rejects_unknown_functions() {
        let expression = Expression::compile("shell(bindings.user)").expect("valid syntax");
        let error = expression
            .evaluate(&context())
            .expect_err("unknown capability must fail");
        assert!(error.to_string().contains("unknown function"));
    }
}
