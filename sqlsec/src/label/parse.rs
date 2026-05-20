use nom::{
    IResult,
    Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::char,
    combinator::map,
    multi::separated_list1,
    sequence::delimited,
};

use crate::label::{AttrReq, Clause, CompareOp, Label};

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn ident(input: &str) -> IResult<&str, &str> {
    take_while1(is_ident_char).parse(input)
}

fn compare_op(input: &str) -> IResult<&str, CompareOp> {
    alt((
        map(tag(">="), |_| CompareOp::Ge),
        map(tag("<="), |_| CompareOp::Le),
        map(tag(">"), |_| CompareOp::Gt),
        map(tag("<"), |_| CompareOp::Lt),
        map(char('='), |_| CompareOp::Eq),
    ))
    .parse(input)
}

fn attr_req(input: &str) -> IResult<&str, AttrReq> {
    map((ident, compare_op, ident), |(k, op, v)| AttrReq {
        key: k.to_string(),
        op,
        value: v.to_string(),
    })
    .parse(input)
}

fn clause(input: &str) -> IResult<&str, Clause> {
    alt((
        delimited(char('('), separated_list1(char('|'), attr_req), char(')')),
        map(attr_req, |r| vec![r]),
    ))
    .parse(input)
}

fn label_expr(input: &str) -> IResult<&str, Label> {
    if input.trim() == "true" {
        return Ok((
            "",
            Label {
                clauses: vec![],
                always_true: true,
            },
        ));
    }

    map(separated_list1(char('&'), clause), |clauses| Label {
        clauses,
        always_true: false,
    })
    .parse(input)
}

pub fn parse(expr: &str) -> Result<Label, String> {
    let trimmed = expr.trim();
    match label_expr(trimmed) {
        Ok(("", label)) => Ok(label),
        Ok((rest, _)) => Err(format!("unexpected trailing: {rest}")),
        Err(e) => Err(format!("parse error: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let label = parse("role=admin").unwrap();
        assert_eq!(label.clauses.len(), 1);
        assert_eq!(label.clauses[0].len(), 1);
        assert_eq!(label.clauses[0][0].op, CompareOp::Eq);
    }

    #[test]
    fn parse_comparison() {
        let label = parse("clearance>=secret").unwrap();
        assert_eq!(label.clauses.len(), 1);
        assert_eq!(label.clauses[0][0].key, "clearance");
        assert_eq!(label.clauses[0][0].op, CompareOp::Ge);
        assert_eq!(label.clauses[0][0].value, "secret");
    }

    #[test]
    fn parse_or_with_comparisons() {
        let label = parse("(clearance>=secret|role=admin)").unwrap();
        assert_eq!(label.clauses.len(), 1);
        assert_eq!(label.clauses[0].len(), 2);
    }

    #[test]
    fn parse_and_of_ors() {
        let label = parse("(role=admin|role=auditor)&clearance>=confidential").unwrap();
        assert_eq!(label.clauses.len(), 2);
    }
}
