use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalDeserialize;
use criterion::{criterion_group, criterion_main, Criterion};
use dynamic_groth16::{
    qap::CircomIncluded, Groth16DynamicV1, Groth16DynamicV2, Groth16DynamicV3, PartialAssignment,
};
use r1cs_permute::{
    r1cs,
    resource::{SerializableMatrices, SerializableProvingKey},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, hint::black_box, io::BufReader, path::PathBuf, time::Duration};

type V1 = Groth16DynamicV1<Bn254, CircomIncluded>;
type V2 = Groth16DynamicV2<Bn254, CircomIncluded>;
type V3 = Groth16DynamicV3<Bn254, CircomIncluded>;

fn benchmarks(c: &mut Criterion) {
    assert!(
        !cfg!(feature = "zkey-reader"),
        "benchmark without zkey-reader; ark-circom forces parallel arkworks features"
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let resources = root.join("resources/tree_depth_20/rln_single");
    let mut reader = BufReader::new(fs::File::open(resources.join("rln_final.arkzkey")).unwrap());
    let pk = SerializableProvingKey::deserialize_uncompressed_unchecked(&mut reader)
        .unwrap()
        .0;
    let matrices: ConstraintMatrices<Fr> =
        SerializableMatrices::deserialize_uncompressed_unchecked(&mut reader)
            .unwrap()
            .into();
    let layout: Value =
        serde_json::from_slice(&fs::read(resources.join("layout.json")).unwrap()).unwrap();
    let graph = fs::read(resources.join("graph.bin")).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&graph)),
        layout["graph_sha256"].as_str().unwrap()
    );
    assert_eq!(layout["public_rows"].as_str(), Some("included"));
    let k = layout["subgroup_size"].as_u64().unwrap() as usize;
    assert_eq!(
        layout["domain_size"].as_u64().unwrap() as usize,
        matrices.num_constraints
    );
    let full =
        r1cs::read_witness(&fs::read(root.join("benches/fixtures/rln_single.wtns")).unwrap())
            .unwrap();
    let mut values: Vec<_> = full.iter().skip(1).copied().map(Some).collect();
    for index in layout["dynamic_indices"].as_array().unwrap() {
        let j = index.as_u64().unwrap() as usize;
        assert!(j > 0 && j < full.len());
        values[j - 1] = None;
    }
    let assignment = PartialAssignment::new(values);
    #[cfg(feature = "parallel")]
    eprintln!(
        "RLN benchmark: Rayon pool has {} threads",
        rayon::current_num_threads()
    );
    #[cfg(not(feature = "parallel"))]
    eprintln!("RLN benchmark: single-threaded arkworks");

    // Verify that all versions produce the same valid proof before timing.
    let setup2 = V2::setup(&pk).unwrap();
    let setup3 = V3::setup(&pk, k).unwrap();
    let partial1 = V1::preprocess(&pk, &assignment).unwrap();
    let partial2 = V2::preprocess(&pk, &matrices, &setup2, &assignment).unwrap();
    let partial3 = V3::preprocess(&pk, &matrices, &setup3, &assignment).unwrap();
    let (r, s) = (Fr::from(7), Fr::from(11));
    let proof1 = V1::finish_with_matrices(
        &pk,
        &partial1,
        r,
        s,
        &matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        &full,
    )
    .unwrap();
    let proof2 =
        V2::finish_with_randomness(&pk, &matrices, &setup2, &full, r, s, &partial2).unwrap();
    let proof3 =
        V3::finish_with_randomness(&pk, &matrices, &setup3, &full, r, s, &partial3).unwrap();
    assert_eq!(proof1, proof2);
    assert_eq!(proof2, proof3);
    assert!(Groth16::<Bn254, CircomIncluded>::verify_proof(
        &prepare_verifying_key(&pk.vk),
        &proof3,
        &full[1..matrices.num_instance_variables]
    )
    .unwrap());

    // Keep serial and parallel Criterion histories separate.
    let name = if cfg!(feature = "parallel") {
        "rln_parallel"
    } else {
        "rln_single_thread"
    };
    let mut group = c.benchmark_group(name);
    group
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    group.bench_function("setup_v2", |b| {
        b.iter(|| V2::setup(black_box(&pk)).unwrap())
    });
    group.bench_function("setup_v3", |b| {
        b.iter(|| V3::setup(black_box(&pk), k).unwrap())
    });
    group.bench_function("preprocess_v1", |b| {
        b.iter(|| V1::preprocess(black_box(&pk), black_box(&assignment)).unwrap())
    });
    group.bench_function("preprocess_v2", |b| {
        b.iter(|| {
            V2::preprocess(
                black_box(&pk),
                black_box(&matrices),
                &setup2,
                black_box(&assignment),
            )
            .unwrap()
        })
    });
    group.bench_function("preprocess_v3", |b| {
        b.iter(|| {
            V3::preprocess(
                black_box(&pk),
                black_box(&matrices),
                &setup3,
                black_box(&assignment),
            )
            .unwrap()
        })
    });
    group.bench_function("finish_v1", |b| {
        b.iter(|| {
            V1::finish_with_matrices(
                black_box(&pk),
                &partial1,
                r,
                s,
                black_box(&matrices),
                matrices.num_instance_variables,
                matrices.num_constraints,
                black_box(&full),
            )
            .unwrap()
        })
    });
    group.bench_function("finish_v2", |b| {
        b.iter(|| {
            V2::finish_with_randomness(
                black_box(&pk),
                black_box(&matrices),
                &setup2,
                black_box(&full),
                r,
                s,
                &partial2,
            )
            .unwrap()
        })
    });
    group.bench_function("finish_v3", |b| {
        b.iter(|| {
            V3::finish_with_randomness(
                black_box(&pk),
                black_box(&matrices),
                &setup3,
                black_box(&full),
                r,
                s,
                &partial3,
            )
            .unwrap()
        })
    });
    group.finish();
}
criterion_group!(benches, benchmarks);
criterion_main!(benches);
