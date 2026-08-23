use thiserror::Error;

use crate::{EvalContext, Expression, ExpressionError};

#[derive(Debug, Clone)]
pub struct CompiledTemplate {
    source: String,
    segments: Vec<TemplateSegment>,
}

impl CompiledTemplate {
    pub fn compile(source: impl Into<String>) -> Result<Self, TemplateError> {
        let source = source.into();
        let mut segments = Vec::new();
        let mut cursor = 0;
        while let Some(relative_start) = source[cursor..].find("{{") {
            let start = cursor + relative_start;
            if start > cursor {
                segments.push(TemplateSegment::Literal(source[cursor..start].to_owned()));
            }
            let expression_start = start + 2;
            let relative_end = source[expression_start..]
                .find("}}")
                .ok_or(TemplateError::UnclosedInterpolation { offset: start })?;
            let end = expression_start + relative_end;
            let expression_source = source[expression_start..end].trim();
            if expression_source.is_empty() {
                return Err(TemplateError::EmptyInterpolation { offset: start });
            }
            segments.push(TemplateSegment::Expression(Expression::compile(
                expression_source,
            )?));
            cursor = end + 2;
        }
        if cursor < source.len() {
            segments.push(TemplateSegment::Literal(source[cursor..].to_owned()));
        }
        Ok(Self { source, segments })
    }

    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn render(&self, context: &EvalContext) -> Result<String, TemplateError> {
        let mut output = String::new();
        for segment in &self.segments {
            match segment {
                TemplateSegment::Literal(value) => output.push_str(value),
                TemplateSegment::Expression(expression) => output.push_str(
                    &expression
                        .evaluate(context)?
                        .render()
                        .map_err(TemplateError::Render)?,
                ),
            }
        }
        Ok(output)
    }

    #[must_use]
    pub fn is_constant(&self) -> bool {
        self.segments
            .iter()
            .all(|segment| matches!(segment, TemplateSegment::Literal(_)))
    }
}

#[derive(Debug, Clone)]
enum TemplateSegment {
    Literal(String),
    Expression(Expression),
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum TemplateError {
    #[error("unclosed template interpolation at byte {offset}")]
    UnclosedInterpolation { offset: usize },
    #[error("empty template interpolation at byte {offset}")]
    EmptyInterpolation { offset: usize },
    #[error(transparent)]
    Expression(#[from] ExpressionError),
    #[error("template value cannot be rendered: {0}")]
    Render(&'static str),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::CompiledTemplate;
    use crate::{EvalContext, Value};

    #[test]
    fn compiles_and_renders_v02_interpolation() {
        let template = CompiledTemplate::compile(
            "hello {{ bindings.name | upper }}, {{ bindings.missing ?? \"guest\" }}",
        )
        .expect("valid template");
        let mut bindings = BTreeMap::new();
        bindings.insert("name".to_owned(), Value::from("Ada"));
        let mut roots = BTreeMap::new();
        roots.insert("bindings".to_owned(), Value::Map(bindings));
        let output = template
            .render(&EvalContext::new(roots))
            .expect("template renders");
        assert_eq!(output, "hello ADA, guest");
    }

    #[test]
    fn reports_unclosed_interpolation() {
        let error = CompiledTemplate::compile("hello {{ bindings.name")
            .expect_err("unclosed template must fail");
        assert!(error.to_string().contains("unclosed"));
    }
}
