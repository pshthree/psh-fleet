use std::time::Duration;

use yara_x::{MetaValue, SourceCode};

use crate::report::Verdict;

pub(crate) struct RuleSource {
    /// YARA namespace, taken from the rule file's stem.
    pub namespace: String,
    /// Shown in compile errors.
    pub origin: String,
    pub source: String,
}

pub(crate) struct RuleSet {
    rules: yara_x::Rules,
    count: usize,
}

pub(crate) struct RuleHit {
    pub name: String,
    pub verdict: Verdict,
}

pub(crate) enum ScanFailure {
    Timeout,
    Other,
}

impl RuleSet {
    pub fn compile(sources: &[RuleSource]) -> Result<Self, String> {
        let mut compiler = yara_x::Compiler::new();
        // Rule files come from a signed bundle and must not pull in other files.
        compiler.enable_includes(false);
        for src in sources {
            compiler.new_namespace(&src.namespace);
            let code = SourceCode::from(src.source.as_str()).with_origin(src.origin.as_str());
            compiler.add_source(code).map_err(|e| e.to_string())?;
        }
        let rules = compiler.build();
        let count = rules.iter().count();
        Ok(Self { rules, count })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn scanner(&self, timeout: Duration) -> yara_x::Scanner<'_> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(timeout);
        scanner
    }
}

/// Rule metadata we read: `verdict = "suspicious"` downgrades a match from the
/// default of malicious, and `name` overrides the detection name.
pub(crate) fn scan(
    scanner: &mut yara_x::Scanner<'_>,
    data: &[u8],
) -> Result<Vec<RuleHit>, ScanFailure> {
    let results = scanner.scan(data).map_err(|e| match e {
        yara_x::ScanError::Timeout => ScanFailure::Timeout,
        _ => ScanFailure::Other,
    })?;
    let mut hits = Vec::new();
    for rule in results.matching_rules() {
        let mut name = None;
        let mut verdict = Verdict::Malicious;
        for (key, value) in rule.metadata() {
            match (key, value) {
                ("name", MetaValue::String(s)) if !s.is_empty() => name = Some(s.to_owned()),
                ("verdict", MetaValue::String(s)) if s.eq_ignore_ascii_case("suspicious") => {
                    verdict = Verdict::Suspicious
                }
                _ => {}
            }
        }
        let name = name.unwrap_or_else(|| format!("{}.{}", rule.namespace(), rule.identifier()));
        hits.push(RuleHit { name, verdict });
    }
    Ok(hits)
}
