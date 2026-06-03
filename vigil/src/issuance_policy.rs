use anyhow::{bail, Result};

use crate::config::IssuancePolicyConfig;

fn is_ip_address(value: &str) -> bool {
    // IPv4
    if value.split('.').count() == 4 {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            return true;
        }
    }
    // IPv6 — contains : but not ://
    value.contains(':') && !value.contains("://")
}

fn is_uri(value: &str) -> bool {
    value.contains("://")
}

fn normalize_dns(name: &str) -> String {
    name.trim().to_lowercase().trim_end_matches('.').to_string()
}

fn is_allowed_dns(
    name: &str,
    suffixes: &[String],
    allow_subdomains: bool,
    allow_bare_suffix: bool,
) -> bool {
    if suffixes.is_empty() {
        return true;
    }
    let normalized = normalize_dns(name);
    suffixes.iter().any(|suffix| {
        let ns = normalize_dns(suffix);
        if ns.is_empty() {
            return false;
        }
        if normalized == ns {
            return allow_bare_suffix;
        }
        allow_subdomains && normalized.ends_with(&format!(".{}", ns))
    })
}

struct CsrIdentifiers {
    dns_names: Vec<String>,
    uri_names: Vec<String>,
    ip_names: Vec<String>,
}

fn extract_identifiers_from_csr(csr_pem: &str) -> CsrIdentifiers {
    let mut dns_names = Vec::new();
    let mut uri_names = Vec::new();
    let mut ip_names = Vec::new();

    let der = match pem::parse(csr_pem) {
        Ok(p) => p.into_contents(),
        Err(_) => return CsrIdentifiers { dns_names, uri_names, ip_names },
    };

    use x509_parser::prelude::FromDer;
    if let Ok((_, csr)) = x509_parser::certification_request::X509CertificationRequest::from_der(&der) {
        // CN
        for attr in csr.certification_request_info.subject.iter_attributes() {
            if let Ok(cn) = attr.attr_value().as_str() {
                let cn = cn.trim();
                if !cn.is_empty() {
                    if is_ip_address(cn) {
                        ip_names.push(cn.to_string());
                    } else {
                        dns_names.push(cn.to_string());
                    }
                }
            }
        }

        // SAN from extensions
        for ext in csr.requested_extensions().into_iter().flatten() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext {
                for name in &san.general_names {
                    match name {
                        x509_parser::extensions::GeneralName::DNSName(dns) => {
                            let s = dns.trim().to_string();
                            if !s.is_empty() { dns_names.push(s); }
                        }
                        x509_parser::extensions::GeneralName::URI(uri) => {
                            let s = uri.trim().to_string();
                            if !s.is_empty() { uri_names.push(s); }
                        }
                        x509_parser::extensions::GeneralName::IPAddress(ip) => {
                            // Convert raw IP bytes to string
                            if ip.len() == 4 {
                                ip_names.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                            } else if ip.len() == 16 {
                                ip_names.push("(ipv6)".to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Deduplicate
    dns_names.sort();
    dns_names.dedup();
    uri_names.sort();
    uri_names.dedup();
    ip_names.sort();
    ip_names.dedup();

    CsrIdentifiers { dns_names, uri_names, ip_names }
}

pub fn validate_issuance_policy(
    csr_pem: &str,
    extra_sans: &[String],
    policy: &IssuancePolicyConfig,
) -> Result<()> {
    let parsed = extract_identifiers_from_csr(csr_pem);

    // Classify extra SANs
    let extra_dns: Vec<String> = extra_sans.iter()
        .filter(|s| !is_ip_address(s) && !is_uri(s))
        .cloned()
        .collect();
    let extra_uris: Vec<String> = extra_sans.iter()
        .filter(|s| is_uri(s))
        .cloned()
        .collect();
    let extra_ips: Vec<String> = extra_sans.iter()
        .filter(|s| is_ip_address(s))
        .cloned()
        .collect();

    let mut dns_names: Vec<String> = parsed.dns_names.iter().chain(extra_dns.iter()).cloned().collect();
    let mut uri_names: Vec<String> = parsed.uri_names.iter().chain(extra_uris.iter()).cloned().collect();
    let mut ip_names: Vec<String> = parsed.ip_names.iter().chain(extra_ips.iter()).cloned().collect();

    dns_names.sort(); dns_names.dedup();
    uri_names.sort(); uri_names.dedup();
    ip_names.sort(); ip_names.dedup();

    if !policy.allow_ip_sans && !ip_names.is_empty() {
        bail!("IP SANs are not allowed by issuance policy: {}", ip_names.join(", "));
    }

    if !policy.allowed_dns_suffixes.is_empty() {
        let disallowed: Vec<&String> = dns_names.iter().filter(|name| {
            !is_allowed_dns(name, &policy.allowed_dns_suffixes, policy.allow_subdomains, policy.allow_bare_suffix)
        }).collect();
        if !disallowed.is_empty() {
            bail!(
                "DNS names are outside allowed issuance policy suffixes: {}",
                disallowed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }

    if !policy.allowed_identity_uri_prefixes.is_empty() {
        let disallowed: Vec<&String> = uri_names.iter().filter(|uri| {
            !policy.allowed_identity_uri_prefixes.iter().any(|prefix| uri.starts_with(prefix))
        }).collect();
        if !disallowed.is_empty() {
            bail!(
                "Identity URIs are outside allowed issuance policy prefixes: {}",
                disallowed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }

    Ok(())
}
