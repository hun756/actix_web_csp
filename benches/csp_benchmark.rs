use actix_web_csp::{
    CspConfig, CspPolicyBuilder, HashAlgorithm, HashGenerator, NonceGenerator, PolicyVerifier,
    Source,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_policy_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_creation");

    group.bench_function("simple_policy", |b| {
        b.iter(|| {
            black_box(
                CspPolicyBuilder::new()
                    .default_src([Source::Self_])
                    .script_src([Source::Self_, Source::UnsafeInline])
                    .style_src([Source::Self_, Source::UnsafeInline])
                    .build_unchecked(),
            )
        })
    });

    group.bench_function("complex_policy", |b| {
        b.iter(|| {
            black_box(
                CspPolicyBuilder::new()
                    .default_src([Source::Self_])
                    .script_src([
                        Source::Self_,
                        Source::Host("cdn.example.com".into()),
                        Source::Host("*.googleapis.com".into()),
                        Source::Nonce("abc123".into()),
                    ])
                    .style_src([
                        Source::Self_,
                        Source::UnsafeInline,
                        Source::Host("fonts.googleapis.com".into()),
                    ])
                    .img_src([
                        Source::Self_,
                        Source::Scheme("data".into()),
                        Source::Host("*.example.com".into()),
                    ])
                    .connect_src([Source::Self_, Source::Host("api.example.com".into())])
                    .font_src([Source::Self_, Source::Host("fonts.gstatic.com".into())])
                    .object_src([Source::None])
                    .media_src([Source::Self_])
                    .frame_src([Source::None])
                    .report_uri("/csp-report")
                    .build_unchecked(),
            )
        })
    });

    group.finish();
}

fn benchmark_header_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_generation");

    let simple_policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([Source::Self_, Source::UnsafeInline])
        .build_unchecked();

    let complex_policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([
            Source::Self_,
            Source::Host("cdn.example.com".into()),
            Source::Host("*.googleapis.com".into()),
            Source::Nonce("abc123def456ghi789".into()),
        ])
        .style_src([
            Source::Self_,
            Source::UnsafeInline,
            Source::Host("fonts.googleapis.com".into()),
        ])
        .img_src([
            Source::Self_,
            Source::Scheme("data".into()),
            Source::Host("*.example.com".into()),
        ])
        .connect_src([Source::Self_, Source::Host("api.example.com".into())])
        .font_src([Source::Self_, Source::Host("fonts.gstatic.com".into())])
        .object_src([Source::None])
        .media_src([Source::Self_])
        .frame_src([Source::None])
        .report_uri("/csp-report")
        .build_unchecked();

    group.bench_function("simple_header", |b| {
        b.iter(|| {
            let mut policy = black_box(simple_policy.clone());
            black_box(policy.header_value().unwrap())
        })
    });

    group.bench_function("complex_header", |b| {
        b.iter(|| {
            let mut policy = black_box(complex_policy.clone());
            black_box(policy.header_value().unwrap())
        })
    });

    group.finish();
}

fn benchmark_nonce_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("nonce_generation");

    let generator = NonceGenerator::new(16);
    let generator_32 = NonceGenerator::new(32);
    let generator_pooled = NonceGenerator::with_capacity(32, 16);

    group.bench_function("nonce_16", |b| b.iter(|| black_box(generator.generate())));

    group.bench_function("nonce_32", |b| {
        b.iter(|| black_box(generator_32.generate()))
    });

    group.bench_function("nonce_pooled", |b| {
        b.iter(|| black_box(generator_pooled.generate()))
    });

    group.finish();
}

fn benchmark_hash_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_generation");

    let script_content = b"console.log('Hello, World!');";
    let large_script = vec![b'x'; 10000];

    group.bench_function("sha256_small", |b| {
        b.iter(|| {
            black_box(HashGenerator::generate(
                HashAlgorithm::Sha256,
                black_box(script_content),
            ))
        })
    });

    group.bench_function("sha384_small", |b| {
        b.iter(|| {
            black_box(HashGenerator::generate(
                HashAlgorithm::Sha384,
                black_box(script_content),
            ))
        })
    });

    group.bench_function("sha512_small", |b| {
        b.iter(|| {
            black_box(HashGenerator::generate(
                HashAlgorithm::Sha512,
                black_box(script_content),
            ))
        })
    });

    group.bench_function("sha256_large", |b| {
        b.iter(|| {
            black_box(HashGenerator::generate(
                HashAlgorithm::Sha256,
                black_box(&large_script),
            ))
        })
    });

    group.finish();
}

fn benchmark_policy_caching(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_caching");

    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([Source::Self_, Source::UnsafeInline])
        .build_unchecked();

    let config = CspConfig::new(policy);

    group.bench_function("cache_miss", |b| {
        b.iter(|| {
            let policy_guard = config.policy();
            let policy = policy_guard.read();
            let mut policy_clone = policy.clone();
            let hash = black_box(policy_clone.hash());
            black_box(config.get_cached_policy(hash))
        })
    });

    group.finish();
}

fn benchmark_policy_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_verification");

    let policy = CspPolicyBuilder::new()
        .default_src([Source::Self_])
        .script_src([
            Source::Self_,
            Source::Host("cdn.example.com".into()),
            Source::Host("*.googleapis.com".into()),
        ])
        .build_unchecked();

    let mut verifier = PolicyVerifier::new(policy);

    group.bench_function("verify_allowed_uri", |b| {
        b.iter(|| {
            black_box(
                verifier
                    .verify_uri(
                        black_box("https://cdn.example.com/script.js"),
                        black_box("script-src"),
                    )
                    .unwrap(),
            )
        })
    });

    group.bench_function("verify_blocked_uri", |b| {
        b.iter(|| {
            black_box(
                verifier
                    .verify_uri(
                        black_box("https://malicious.com/script.js"),
                        black_box("script-src"),
                    )
                    .unwrap(),
            )
        })
    });

    group.bench_function("verify_hash", |b| {
        let content = b"console.log('test');";
        b.iter(|| {
            black_box(
                verifier
                    .verify_hash(black_box(content), black_box("script-src"))
                    .unwrap(),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_policy_creation,
    benchmark_header_generation,
    benchmark_nonce_generation,
    benchmark_hash_generation,
    benchmark_policy_caching,
    benchmark_policy_verification
);

criterion_main!(benches);
