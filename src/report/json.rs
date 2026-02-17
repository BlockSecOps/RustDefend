use anyhow::Result;

use super::Reporter;
use crate::scanner::finding::Finding;

pub struct JsonReporter;

impl Reporter for JsonReporter {
    fn render(&self, findings: &[Finding]) -> Result<String> {
        Ok(serde_json::to_string_pretty(findings)?)
    }
}
