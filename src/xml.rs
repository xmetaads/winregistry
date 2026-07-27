//! A small, dependency-free XML reader.
//!
//! Scoped deliberately to what ADMX and Group Policy Preferences files actually
//! contain: elements, attributes, text, CDATA, comments, character and the five
//! predefined entity references. It is **not** a general XML processor — there
//! is no DTD handling, no external entity resolution and no XInclude, and that
//! is a feature: an XML parser that resolves external entities in a tool that
//! reads files from a policy share is an XXE vulnerability waiting to happen.
//!
//! Namespace prefixes are stripped rather than resolved. ADMX and GPP both put
//! everything in one namespace, so `q1:policy` and `policy` mean the same thing
//! here, and matching on the local name is what callers want.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    /// Local name with any namespace prefix removed.
    pub name: String,
    pub attrs: BTreeMap<String, String>,
    pub children: Vec<Node>,
    /// Concatenated direct text content, whitespace-trimmed.
    pub text: String,
}

impl Node {
    pub fn attr(&self, name: &str) -> Option<&str> {
        // Attribute names are case-sensitive in XML, but real-world ADMX has
        // enough inconsistency that a case-insensitive fallback saves grief.
        self.attrs
            .get(name)
            .or_else(|| self.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v))
            .map(String::as_str)
    }

    /// Direct children with this local name. The name is copied so the returned
    /// iterator borrows only `self`, not the caller's string.
    pub fn kids<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a Node> + 'a {
        let want = name.to_ascii_lowercase();
        self.children
            .iter()
            .filter(move |c| c.name.to_ascii_lowercase() == want)
    }

    pub fn kid(&self, name: &str) -> Option<&Node> {
        self.kids(name).next()
    }

    /// Every descendant with this local name, in document order.
    pub fn descendants<'a>(&'a self, name: &'a str) -> Vec<&'a Node> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(n) = stack.pop() {
            if n.name.eq_ignore_ascii_case(name) {
                out.push(n);
            }
            for c in n.children.iter().rev() {
                stack.push(c);
            }
        }
        out
    }
}

pub fn parse(text: &str) -> Result<Node, String> {
    let b: Vec<char> = text.chars().collect();
    let mut p = P { b: &b, i: 0, depth: 0 };
    p.prolog()?;
    let root = p.element()?;
    p.ws_and_misc()?;
    if p.i < p.b.len() {
        return Err(format!("trailing content after the root element at character {}", p.i + 1));
    }
    Ok(root)
}

/// A pathological nesting depth is the classic XML denial-of-service. A policy
/// template is a handful of levels deep; 256 is far past anything legitimate.
const MAX_DEPTH: usize = 256;

struct P<'a> {
    b: &'a [char],
    i: usize,
    depth: usize,
}

impl<'a> P<'a> {
    fn at(&self) -> Option<char> {
        self.b.get(self.i).copied()
    }

    fn starts(&self, s: &str) -> bool {
        let n = s.chars().count();
        self.i + n <= self.b.len() && self.b[self.i..self.i + n].iter().copied().eq(s.chars())
    }

    fn skip(&mut self, n: usize) {
        self.i += n;
    }

    fn ws(&mut self) {
        while matches!(self.at(), Some(c) if c.is_whitespace()) {
            self.i += 1;
        }
    }

    /// Skip whitespace, comments and processing instructions.
    fn ws_and_misc(&mut self) -> Result<(), String> {
        loop {
            self.ws();
            if self.starts("<!--") {
                self.skip(4);
                while self.i < self.b.len() && !self.starts("-->") {
                    self.i += 1;
                }
                if !self.starts("-->") {
                    return Err("unterminated comment".into());
                }
                self.skip(3);
            } else if self.starts("<?") {
                self.skip(2);
                while self.i < self.b.len() && !self.starts("?>") {
                    self.i += 1;
                }
                if !self.starts("?>") {
                    return Err("unterminated processing instruction".into());
                }
                self.skip(2);
            } else {
                return Ok(());
            }
        }
    }

    fn prolog(&mut self) -> Result<(), String> {
        self.ws_and_misc()?;
        if self.starts("<!DOCTYPE") {
            // Refused rather than skipped: a DOCTYPE is where external entity
            // and billion-laughs attacks live, and neither ADMX nor GPP needs one.
            return Err(
                "this file declares a DOCTYPE, which regx does not process (external entities \
                 are an injection risk). Remove the DOCTYPE, or convert the file first."
                    .into(),
            );
        }
        Ok(())
    }

    fn name(&mut self) -> Result<String, String> {
        let start = self.i;
        while let Some(c) = self.at() {
            if c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | ':') {
                self.i += 1;
            } else {
                break;
            }
        }
        if start == self.i {
            return Err(format!("expected a name at character {}", self.i + 1));
        }
        let raw: String = self.b[start..self.i].iter().collect();
        // Strip the namespace prefix; callers match on local names.
        Ok(match raw.rsplit_once(':') {
            Some((_, local)) if !local.is_empty() => local.to_string(),
            _ => raw,
        })
    }

    fn element(&mut self) -> Result<Node, String> {
        if self.depth >= MAX_DEPTH {
            return Err(format!("element nesting deeper than {MAX_DEPTH} levels"));
        }
        if self.at() != Some('<') {
            return Err(format!("expected '<' at character {}", self.i + 1));
        }
        self.skip(1);
        let name = self.name()?;

        let mut attrs = BTreeMap::new();
        loop {
            self.ws();
            match self.at() {
                Some('/') => {
                    self.skip(1);
                    if self.at() != Some('>') {
                        return Err(format!("expected '>' after '/' at character {}", self.i + 1));
                    }
                    self.skip(1);
                    return Ok(Node { name, attrs, children: Vec::new(), text: String::new() });
                }
                Some('>') => {
                    self.skip(1);
                    break;
                }
                Some(_) => {
                    let key = self.name()?;
                    self.ws();
                    if self.at() != Some('=') {
                        return Err(format!("expected '=' after attribute {key:?}"));
                    }
                    self.skip(1);
                    self.ws();
                    let value = self.attr_value()?;
                    if attrs.insert(key.clone(), value).is_some() {
                        return Err(format!("duplicate attribute {key:?} on <{name}>"));
                    }
                }
                None => return Err(format!("file ends inside <{name}>")),
            }
        }

        // Content.
        let mut children = Vec::new();
        let mut text = String::new();
        loop {
            if self.i >= self.b.len() {
                return Err(format!("file ends before </{name}>"));
            }
            if self.starts("</") {
                self.skip(2);
                let close = self.name()?;
                self.ws();
                if self.at() != Some('>') {
                    return Err(format!("expected '>' closing </{close}>"));
                }
                self.skip(1);
                if !close.eq_ignore_ascii_case(&name) {
                    return Err(format!("</{close}> closes <{name}>"));
                }
                return Ok(Node {
                    name,
                    attrs,
                    children,
                    text: text.trim().to_string(),
                });
            }
            if self.starts("<!--") {
                self.ws_and_misc()?;
                continue;
            }
            if self.starts("<![CDATA[") {
                self.skip(9);
                let start = self.i;
                while self.i < self.b.len() && !self.starts("]]>") {
                    self.i += 1;
                }
                if !self.starts("]]>") {
                    return Err("unterminated CDATA section".into());
                }
                text.extend(self.b[start..self.i].iter());
                self.skip(3);
                continue;
            }
            if self.starts("<?") {
                self.ws_and_misc()?;
                continue;
            }
            if self.at() == Some('<') {
                self.depth += 1;
                let child = self.element();
                self.depth -= 1;
                children.push(child?);
                continue;
            }
            // Character data.
            let c = self.at().unwrap();
            if c == '&' {
                text.push_str(&self.entity()?);
            } else {
                text.push(c);
                self.i += 1;
            }
        }
    }

    fn attr_value(&mut self) -> Result<String, String> {
        let quote = match self.at() {
            Some(q @ ('"' | '\'')) => q,
            _ => return Err(format!("expected a quoted attribute value at character {}", self.i + 1)),
        };
        self.skip(1);
        let mut out = String::new();
        loop {
            match self.at() {
                None => return Err("file ends inside an attribute value".into()),
                Some(c) if c == quote => {
                    self.skip(1);
                    return Ok(out);
                }
                Some('&') => out.push_str(&self.entity()?),
                Some('<') => return Err("a raw '<' is not allowed in an attribute value".into()),
                Some(c) => {
                    out.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// The five predefined entities plus numeric character references. Anything
    /// else would need a DTD, which is refused in `prolog`.
    fn entity(&mut self) -> Result<String, String> {
        self.skip(1); // '&'
        let start = self.i;
        while matches!(self.at(), Some(c) if c != ';' && !c.is_whitespace() && c != '<') {
            self.i += 1;
        }
        if self.at() != Some(';') {
            return Err(format!("unterminated entity reference at character {}", start));
        }
        let name: String = self.b[start..self.i].iter().collect();
        self.skip(1);

        Ok(match name.as_str() {
            "lt" => "<".into(),
            "gt" => ">".into(),
            "amp" => "&".into(),
            "quot" => "\"".into(),
            "apos" => "'".into(),
            n if n.starts_with("#x") || n.starts_with("#X") => {
                let cp = u32::from_str_radix(&n[2..], 16)
                    .map_err(|_| format!("invalid character reference &{n};"))?;
                char::from_u32(cp)
                    .ok_or_else(|| format!("&{n}; is not a valid character"))?
                    .to_string()
            }
            n if n.starts_with('#') => {
                let cp: u32 = n[1..]
                    .parse()
                    .map_err(|_| format!("invalid character reference &{n};"))?;
                char::from_u32(cp)
                    .ok_or_else(|| format!("&{n}; is not a valid character"))?
                    .to_string()
            }
            other => {
                return Err(format!(
                    "unknown entity &{other};; regx resolves only the five predefined entities \
                     and numeric references"
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_elements_attributes_and_text() {
        let n = parse(r#"<?xml version="1.0"?><root a="1" b='two'><child>hi</child><!-- c --></root>"#).unwrap();
        assert_eq!(n.name, "root");
        assert_eq!(n.attr("a"), Some("1"));
        assert_eq!(n.attr("b"), Some("two"));
        assert_eq!(n.kid("child").unwrap().text, "hi");
    }

    #[test]
    fn strips_namespace_prefixes() {
        let n = parse(r#"<q1:policyDefinitions xmlns:q1="urn:x"><q1:policy name="P"/></q1:policyDefinitions>"#).unwrap();
        assert_eq!(n.name, "policyDefinitions");
        assert_eq!(n.kid("policy").unwrap().attr("name"), Some("P"));
    }

    #[test]
    fn resolves_entities_and_cdata() {
        let n = parse(r#"<r t="a&amp;b&#65;">x &lt;y&gt; <![CDATA[raw <&> ]]>z</r>"#).unwrap();
        assert_eq!(n.attr("t"), Some("a&bA"));
        assert_eq!(n.text, "x <y> raw <&> z");
    }

    #[test]
    fn self_closing_and_nesting() {
        let n = parse("<a><b/><c><d/></c></a>").unwrap();
        assert_eq!(n.children.len(), 2);
        assert_eq!(n.descendants("d").len(), 1);
    }

    #[test]
    fn doctype_is_refused_not_skipped() {
        let e = parse("<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///c:/x\">]><r/>").unwrap_err();
        assert!(e.contains("DOCTYPE"), "{e}");
    }

    #[test]
    fn rejects_mismatched_tags_and_duplicates() {
        assert!(parse("<a></b>").is_err());
        assert!(parse("<a x='1' x='2'/>").is_err());
        assert!(parse("<a>").is_err());
        assert!(parse("<a/><b/>").is_err(), "only one root element");
    }

    #[test]
    fn unknown_entity_is_an_error_not_silent_loss() {
        let e = parse("<r>&xxe;</r>").unwrap_err();
        assert!(e.contains("unknown entity"), "{e}");
    }

    #[test]
    fn depth_is_bounded() {
        let deep = "<a>".repeat(400) + &"</a>".repeat(400);
        assert!(parse(&deep).is_err());
    }
}
