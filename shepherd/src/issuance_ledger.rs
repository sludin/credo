use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::types::{
    CaRateLimits, DomainQuotaStatus, IdentifierSetQuotaStatus, IssuanceEvent, ManagedAssignment,
};

// ---------------------------------------------------------------------------
// IssuanceLedger
// ---------------------------------------------------------------------------

pub struct IssuanceLedger {
    events: Vec<IssuanceEvent>,
    path: PathBuf,
    max_window_days: i64,
}

impl IssuanceLedger {
    /// Load ledger from disk, pruning events older than `max_window_days`.
    /// Missing file → empty ledger (no error). Corrupt file → warn and start empty.
    pub fn load(path: PathBuf, max_window_days: i64) -> Self {
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<IssuanceEvent>>(&content) {
                Ok(events) => {
                    let mut ledger = Self {
                        events,
                        path,
                        max_window_days,
                    };
                    ledger.prune();
                    ledger
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Failed to parse issuance ledger; starting empty"
                    );
                    Self {
                        events: vec![],
                        path,
                        max_window_days,
                    }
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self {
                events: vec![],
                path,
                max_window_days,
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to read issuance ledger; starting empty"
                );
                Self {
                    events: vec![],
                    path,
                    max_window_days,
                }
            }
        }
    }

    /// Append a new issuance event, prune old entries, and flush to disk.
    pub fn append(&mut self, event: IssuanceEvent) -> Result<()> {
        self.events.push(event);
        self.prune();
        self.flush()
    }

    /// Count events for a registered domain + CA within the given window.
    pub fn domain_count_window(&self, registered_domain: &str, ca: &str, window_days: i64) -> u32 {
        let cutoff = Utc::now() - Duration::days(window_days);
        self.events
            .iter()
            .filter(|e| {
                e.registered_domain == registered_domain && e.ca == ca && e.issued_at > cutoff
            })
            .count() as u32
    }

    /// Count events for an exact SAN set + CA within the given window.
    pub fn identifier_count_window(&self, sans: &[String], ca: &str, window_days: i64) -> u32 {
        let cutoff = Utc::now() - Duration::days(window_days);
        self.events
            .iter()
            .filter(|e| e.ca == ca && e.sans == sans && e.issued_at > cutoff)
            .count() as u32
    }

    /// Check rate limits for a proposed issuance.
    /// Returns `Some(retry_after)` if gated, or `None` if the issuance is allowed.
    /// If `limits` is `None`, the CA is unconstrained and `None` is always returned.
    pub fn rate_limit_check(
        &self,
        sans: &[String],
        ca: &str,
        limits: Option<&CaRateLimits>,
    ) -> Option<DateTime<Utc>> {
        let limits = limits?; // None limits → no gate
        let mut retry_after: Option<DateTime<Utc>> = None;

        if let Some(domain_limit) = &limits.certificates_per_domain {
            let window_days = domain_limit.window_days as i64;
            let cutoff = Utc::now() - Duration::days(window_days);
            let registered_domains: HashSet<String> = sans
                .iter()
                .filter_map(|san| extract_registered_domain(san))
                .collect();

            for domain in &registered_domains {
                let domain_events: Vec<&IssuanceEvent> = self
                    .events
                    .iter()
                    .filter(|e| {
                        e.ca == ca && e.registered_domain == *domain && e.issued_at > cutoff
                    })
                    .collect();

                if domain_events.len() as u32 >= domain_limit.count {
                    let oldest = domain_events.iter().map(|e| e.issued_at).min().unwrap();
                    let r = oldest + Duration::days(window_days);
                    retry_after = Some(retry_after.map_or(r, |prev: DateTime<Utc>| prev.max(r)));
                }
            }
        }

        if let Some(dup_limit) = &limits.duplicate_certificates {
            let window_days = dup_limit.window_days as i64;
            let cutoff = Utc::now() - Duration::days(window_days);
            let id_events: Vec<&IssuanceEvent> = self
                .events
                .iter()
                .filter(|e| e.ca == ca && e.sans == sans && e.issued_at > cutoff)
                .collect();

            if id_events.len() as u32 >= dup_limit.count {
                let oldest = id_events.iter().map(|e| e.issued_at).min().unwrap();
                let r = oldest + Duration::days(window_days);
                retry_after = Some(retry_after.map_or(r, |prev: DateTime<Utc>| prev.max(r)));
            }
        }

        retry_after
    }

    /// Compute per-registered-domain quota status for the API response.
    /// Only includes (domain, CA) pairs where the CA has `certificates_per_domain` configured.
    pub fn domain_quotas(
        &self,
        ca_limits: &HashMap<String, CaRateLimits>,
    ) -> Vec<DomainQuotaStatus> {
        let mut groups: HashMap<(String, String), Vec<&IssuanceEvent>> = HashMap::new();
        for event in &self.events {
            if ca_limits
                .get(&event.ca)
                .and_then(|rl| rl.certificates_per_domain.as_ref())
                .is_some()
            {
                groups
                    .entry((event.registered_domain.clone(), event.ca.clone()))
                    .or_default()
                    .push(event);
            }
        }

        let mut result: Vec<DomainQuotaStatus> = groups
            .into_iter()
            .filter_map(|((domain, ca), all_evts)| {
                let domain_limit = ca_limits.get(&ca)?.certificates_per_domain.as_ref()?;
                let window_days = domain_limit.window_days as i64;
                let cutoff = Utc::now() - Duration::days(window_days);
                let evts_in_window: Vec<_> =
                    all_evts.iter().filter(|e| e.issued_at > cutoff).collect();
                let issued = evts_in_window.len() as u32;
                let next_slot_at = if issued >= domain_limit.count {
                    let oldest = evts_in_window.iter().map(|e| e.issued_at).min()?;
                    Some(oldest + Duration::days(window_days))
                } else {
                    None
                };
                Some(DomainQuotaStatus {
                    registered_domain: domain,
                    ca,
                    issued,
                    limit: domain_limit.count,
                    window_days: domain_limit.window_days,
                    next_slot_at,
                })
            })
            .collect();

        result.sort_by(|a, b| {
            a.registered_domain
                .cmp(&b.registered_domain)
                .then(a.ca.cmp(&b.ca))
        });
        result
    }

    /// Compute per-cert (exact SAN set) quota status for the API response.
    /// Only includes assignments whose CA has `duplicate_certificates` configured.
    pub fn identifier_set_quotas(
        &self,
        assignments: &[ManagedAssignment],
        ca_limits: &HashMap<String, CaRateLimits>,
    ) -> Vec<IdentifierSetQuotaStatus> {
        assignments
            .iter()
            .filter_map(|assignment| {
                let dup_limit = ca_limits
                    .get(&assignment.ca)?
                    .duplicate_certificates
                    .as_ref()?;
                let window_days = dup_limit.window_days as i64;
                let cutoff = Utc::now() - Duration::days(window_days);
                let sans = canonical_sans(assignment);
                let ca = &assignment.ca;

                let matching: Vec<&IssuanceEvent> = self
                    .events
                    .iter()
                    .filter(|e| e.ca == *ca && e.sans == sans && e.issued_at > cutoff)
                    .collect();

                let issued = matching.len() as u32;
                let next_slot_at = if issued >= dup_limit.count {
                    let oldest = matching.iter().map(|e| e.issued_at).min()?;
                    Some(oldest + Duration::days(window_days))
                } else {
                    None
                };

                Some(IdentifierSetQuotaStatus {
                    cert_name: assignment.cert_name.clone(),
                    sans,
                    ca: ca.clone(),
                    issued,
                    limit: dup_limit.count,
                    window_days: dup_limit.window_days,
                    next_slot_at,
                })
            })
            .collect()
    }

    fn prune(&mut self) {
        let cutoff = Utc::now() - Duration::days(self.max_window_days);
        self.events.retain(|e| e.issued_at > cutoff);
    }

    fn flush(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.events)?;
        std::fs::write(&self.path, &json)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the eTLD+1 registered domain from a hostname using the Public Suffix List.
/// Returns `None` if the hostname has no valid registrable domain.
pub fn extract_registered_domain(hostname: &str) -> Option<String> {
    use psl::Psl;
    let hostname = hostname.trim_start_matches("*."); // strip wildcard prefix
    psl::List
        .domain(hostname.as_bytes())
        .map(|d| String::from_utf8_lossy(d.as_bytes()).into_owned())
}

/// Build the canonical sorted, deduplicated SAN list for an assignment.
/// The primary domain (if set) is always included.
pub fn canonical_sans(assignment: &ManagedAssignment) -> Vec<String> {
    let mut sans: Vec<String> = assignment.sans.clone();
    if let Some(ref domain) = assignment.domain {
        if !sans.contains(domain) {
            sans.push(domain.clone());
        }
    }
    sans.sort();
    sans.dedup();
    sans
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tempfile::TempDir;

    fn make_event(
        cert_name: &str,
        registered_domain: &str,
        sans: Vec<String>,
        ca: &str,
        days_ago: i64,
    ) -> IssuanceEvent {
        IssuanceEvent {
            cert_name: cert_name.to_string(),
            ca: ca.to_string(),
            registered_domain: registered_domain.to_string(),
            sans,
            issued_at: Utc::now() - Duration::days(days_ago),
            fingerprint256: format!("FP:{cert_name}:{days_ago}"),
        }
    }

    fn le_limits() -> crate::types::CaRateLimits {
        use crate::types::{CaRateLimit, CaRateLimits};
        CaRateLimits {
            certificates_per_domain: Some(CaRateLimit {
                count: 50,
                window_days: 7,
            }),
            duplicate_certificates: Some(CaRateLimit {
                count: 5,
                window_days: 7,
            }),
        }
    }

    fn empty_ledger(dir: &TempDir) -> IssuanceLedger {
        IssuanceLedger::load(dir.path().join("ledger.json"), 7)
    }

    // -----------------------------------------------------------------------
    // domain_count_window
    // -----------------------------------------------------------------------

    #[test]
    fn domain_count_within_window() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        ledger.events.push(make_event(
            "c1",
            "example.com",
            vec!["a.example.com".into()],
            "le",
            1,
        ));
        ledger.events.push(make_event(
            "c2",
            "example.com",
            vec!["b.example.com".into()],
            "le",
            6,
        ));
        ledger.events.push(make_event(
            "c3",
            "example.com",
            vec!["c.example.com".into()],
            "le",
            8,
        )); // outside

        assert_eq!(ledger.domain_count_window("example.com", "le", 7), 2);
    }

    #[test]
    fn domain_count_excludes_different_ca() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        ledger.events.push(make_event(
            "c1",
            "example.com",
            vec!["a.example.com".into()],
            "le",
            1,
        ));
        ledger.events.push(make_event(
            "c2",
            "example.com",
            vec!["b.example.com".into()],
            "vigil",
            1,
        ));

        assert_eq!(ledger.domain_count_window("example.com", "le", 7), 1);
    }

    #[test]
    fn domain_count_excludes_different_domain() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        ledger.events.push(make_event(
            "c1",
            "example.com",
            vec!["a.example.com".into()],
            "le",
            1,
        ));
        ledger.events.push(make_event(
            "c2",
            "other.com",
            vec!["b.other.com".into()],
            "le",
            1,
        ));

        assert_eq!(ledger.domain_count_window("example.com", "le", 7), 1);
    }

    // -----------------------------------------------------------------------
    // identifier_count_window
    // -----------------------------------------------------------------------

    #[test]
    fn identifier_count_requires_exact_san_match() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        let sans = vec!["api.example.com".to_string(), "www.example.com".to_string()];
        ledger
            .events
            .push(make_event("c1", "example.com", sans.clone(), "le", 1));
        ledger.events.push(make_event(
            "c2",
            "example.com",
            vec!["api.example.com".into()],
            "le",
            1,
        )); // different set

        assert_eq!(ledger.identifier_count_window(&sans, "le", 7), 1);
    }

    #[test]
    fn identifier_count_within_window() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        let sans = vec!["api.example.com".to_string()];
        ledger
            .events
            .push(make_event("c1", "example.com", sans.clone(), "le", 1));
        ledger
            .events
            .push(make_event("c2", "example.com", sans.clone(), "le", 6));
        ledger
            .events
            .push(make_event("c3", "example.com", sans.clone(), "le", 8)); // outside

        assert_eq!(ledger.identifier_count_window(&sans, "le", 7), 2);
    }

    // -----------------------------------------------------------------------
    // prune
    // -----------------------------------------------------------------------

    #[test]
    fn pruning_removes_events_older_than_7_days() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        ledger.events.push(make_event(
            "old",
            "example.com",
            vec!["a.example.com".into()],
            "le",
            8,
        ));
        ledger.events.push(make_event(
            "new",
            "example.com",
            vec!["b.example.com".into()],
            "le",
            1,
        ));

        ledger.prune();

        assert_eq!(ledger.events.len(), 1);
        assert_eq!(ledger.events[0].cert_name, "new");
    }

    // -----------------------------------------------------------------------
    // load
    // -----------------------------------------------------------------------

    #[test]
    fn load_from_missing_file_starts_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");
        let ledger = IssuanceLedger::load(path, 7);
        assert!(ledger.events.is_empty());
    }

    #[test]
    fn load_from_corrupt_file_starts_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.json");
        std::fs::write(&path, b"not valid json at all{{{{").unwrap();
        let ledger = IssuanceLedger::load(path, 7);
        assert!(ledger.events.is_empty());
    }

    #[test]
    fn load_prunes_stale_events() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.json");
        let old_event = make_event("old", "example.com", vec!["a.example.com".into()], "le", 8);
        let json = serde_json::to_string(&vec![old_event]).unwrap();
        std::fs::write(&path, json).unwrap();

        let ledger = IssuanceLedger::load(path, 7);
        assert!(ledger.events.is_empty());
    }

    // -----------------------------------------------------------------------
    // round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_persist_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.json");
        let sans = vec!["api.example.com".to_string()];

        {
            let mut ledger = IssuanceLedger::load(path.clone(), 7);
            let event = make_event("api-cert", "example.com", sans.clone(), "le", 1);
            ledger.append(event).unwrap();
        }

        let ledger2 = IssuanceLedger::load(path, 7);
        assert_eq!(ledger2.domain_count_window("example.com", "le", 7), 1);
        assert_eq!(ledger2.identifier_count_window(&sans, "le", 7), 1);
    }

    // -----------------------------------------------------------------------
    // rate_limit_check — domain gate
    // -----------------------------------------------------------------------

    #[test]
    fn domain_gate_blocks_at_50() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        for i in 0..50u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                vec![format!("sub{i}.example.com")],
                "le",
                1,
            ));
        }
        let sans = vec!["new.example.com".to_string()];
        assert!(ledger
            .rate_limit_check(&sans, "le", Some(&le_limits()))
            .is_some());
    }

    #[test]
    fn domain_gate_allows_at_49() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        for i in 0..49u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                vec![format!("sub{i}.example.com")],
                "le",
                1,
            ));
        }
        let sans = vec!["new.example.com".to_string()];
        assert!(ledger
            .rate_limit_check(&sans, "le", Some(&le_limits()))
            .is_none());
    }

    // -----------------------------------------------------------------------
    // rate_limit_check — identifier set gate
    // -----------------------------------------------------------------------

    #[test]
    fn identifier_gate_blocks_at_5() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        let sans = vec!["api.example.com".to_string()];
        for i in 0..5u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                sans.clone(),
                "le",
                1,
            ));
        }
        assert!(ledger
            .rate_limit_check(&sans, "le", Some(&le_limits()))
            .is_some());
    }

    #[test]
    fn identifier_gate_allows_at_4() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        let sans = vec!["api.example.com".to_string()];
        for i in 0..4u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                sans.clone(),
                "le",
                1,
            ));
        }
        assert!(ledger
            .rate_limit_check(&sans, "le", Some(&le_limits()))
            .is_none());
    }

    // -----------------------------------------------------------------------
    // rate_limit_check — retry_after correctness
    // -----------------------------------------------------------------------

    #[test]
    fn retry_after_is_oldest_event_plus_7_days() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        let sans = vec!["api.example.com".to_string()];

        let oldest_issued_at = Utc::now() - Duration::days(3);
        ledger.events.push(IssuanceEvent {
            cert_name: "c0".into(),
            ca: "le".into(),
            registered_domain: "example.com".into(),
            sans: sans.clone(),
            issued_at: oldest_issued_at,
            fingerprint256: "FP:0".into(),
        });
        for i in 1..5u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                sans.clone(),
                "le",
                1,
            ));
        }

        let retry = ledger
            .rate_limit_check(&sans, "le", Some(&le_limits()))
            .unwrap();
        let expected = oldest_issued_at + Duration::days(7);
        let diff = (retry - expected).num_seconds().abs();
        assert!(
            diff <= 1,
            "retry_after should be oldest_issued_at + 7 days, got diff {diff}s"
        );
    }

    // -----------------------------------------------------------------------
    // extract_registered_domain
    // -----------------------------------------------------------------------

    #[test]
    fn registered_domain_from_subdomain() {
        assert_eq!(
            extract_registered_domain("api.example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn registered_domain_strips_wildcard() {
        assert_eq!(
            extract_registered_domain("*.example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn registered_domain_handles_co_uk() {
        assert_eq!(
            extract_registered_domain("api.example.co.uk"),
            Some("example.co.uk".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // canonical_sans
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_sans_includes_domain_and_sorts() {
        use crate::types::ManagedAssignment;
        let assignment = ManagedAssignment {
            cert_name: "test".into(),
            corgi: None,
            ca: "le".into(),
            domain: Some("www.example.com".into()),
            sans: vec!["api.example.com".into()],
            renew_before_days: None,
            days: None,
            identity_uri: None,
            validation: None,
            cert_mode: None,
            key_mode: None,
            cert_owner: None,
            cert_group: None,
            key_owner: None,
            key_group: None,
            key_algorithm: None,
            hooks: None,
        };
        let result = canonical_sans(&assignment);
        assert_eq!(result, vec!["api.example.com", "www.example.com"]);
    }

    #[test]
    fn canonical_sans_deduplicates() {
        use crate::types::ManagedAssignment;
        let assignment = ManagedAssignment {
            cert_name: "test".into(),
            corgi: None,
            ca: "le".into(),
            domain: Some("api.example.com".into()), // duplicate of sans[0]
            sans: vec!["api.example.com".into()],
            renew_before_days: None,
            days: None,
            identity_uri: None,
            validation: None,
            cert_mode: None,
            key_mode: None,
            cert_owner: None,
            cert_group: None,
            key_owner: None,
            key_group: None,
            key_algorithm: None,
            hooks: None,
        };
        let result = canonical_sans(&assignment);
        assert_eq!(result, vec!["api.example.com"]);
    }

    // -----------------------------------------------------------------------
    // rate_limit_check — no limits (None)
    // -----------------------------------------------------------------------

    #[test]
    fn unlimited_ca_never_blocked() {
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        let sans = vec!["api.example.com".to_string()];
        for i in 0..100u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                sans.clone(),
                "vigil",
                1,
            ));
        }
        // None limits = no rate limiting
        assert!(ledger.rate_limit_check(&sans, "vigil", None).is_none());
    }

    #[test]
    fn custom_window_uses_configured_days() {
        use crate::types::{CaRateLimit, CaRateLimits};
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        let sans = vec!["api.example.com".to_string()];
        // 3 events, all within the last 5 days (days_ago = 1)
        for i in 0..3u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                sans.clone(),
                "myca",
                1,
            ));
        }
        let limits = CaRateLimits {
            certificates_per_domain: None,
            duplicate_certificates: Some(CaRateLimit {
                count: 3,
                window_days: 5,
            }),
        };
        // Should be blocked (3 >= 3 within 5 days)
        assert!(ledger
            .rate_limit_check(&sans, "myca", Some(&limits))
            .is_some());
    }

    #[test]
    fn custom_window_outside_window_not_blocked() {
        use crate::types::{CaRateLimit, CaRateLimits};
        let dir = TempDir::new().unwrap();
        // Use max_window_days=30 so events at day 11 aren't pruned
        let mut ledger = IssuanceLedger::load(dir.path().join("ledger.json"), 30);
        let sans = vec!["api.example.com".to_string()];
        // 3 events, all 11 days ago (outside a 5-day window)
        for i in 0..3u32 {
            ledger.events.push(make_event(
                &format!("c{i}"),
                "example.com",
                sans.clone(),
                "myca",
                11,
            ));
        }
        let limits = CaRateLimits {
            certificates_per_domain: None,
            duplicate_certificates: Some(CaRateLimit {
                count: 3,
                window_days: 5,
            }),
        };
        // Events are outside the 5-day window → not blocked
        assert!(ledger
            .rate_limit_check(&sans, "myca", Some(&limits))
            .is_none());
    }

    // -----------------------------------------------------------------------
    // domain_quotas — CA-aware
    // -----------------------------------------------------------------------

    #[test]
    fn domain_quotas_only_shows_cas_with_limits() {
        use crate::types::{CaRateLimit, CaRateLimits};
        use std::collections::HashMap;
        let dir = TempDir::new().unwrap();
        let mut ledger = empty_ledger(&dir);
        ledger.events.push(make_event(
            "c1",
            "example.com",
            vec!["a.example.com".into()],
            "le",
            1,
        ));
        ledger.events.push(make_event(
            "c2",
            "example.com",
            vec!["b.example.com".into()],
            "vigil",
            1,
        ));

        let mut ca_limits = HashMap::new();
        ca_limits.insert(
            "le".into(),
            CaRateLimits {
                certificates_per_domain: Some(CaRateLimit {
                    count: 50,
                    window_days: 7,
                }),
                duplicate_certificates: None,
            },
        );
        // vigil not in map → unlimited → should not appear in quotas

        let quotas = ledger.domain_quotas(&ca_limits);
        assert_eq!(quotas.len(), 1);
        assert_eq!(quotas[0].ca, "le");
        assert_eq!(quotas[0].limit, 50);
        assert_eq!(quotas[0].window_days, 7);
        assert_eq!(quotas[0].issued, 1);
    }
}
