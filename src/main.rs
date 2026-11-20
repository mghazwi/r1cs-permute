mod graph;

use ark_bn254::{Bn254, Fr};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dynamic_groth16::dynamic::v3::permutation::permute_rows;
use dynamic_groth16::{qap::CircomIncluded, Groth16DynamicV3, PartialAssignment};
use r1cs_permute::{
    r1cs,
    resource::{SerializableMatrices, SerializableProvingKey},
};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::OpenOptions,
    io::{BufReader, BufWriter, Write},
    path::Path,
};

type AppResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn create_new(path: &str) -> AppResult<BufWriter<fs::File>> {
    Ok(BufWriter::new(
        OpenOptions::new().write(true).create_new(true).open(path)?,
    ))
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn read_indices(path: &str, variables: usize) -> AppResult<Vec<usize>> {
    let text = fs::read_to_string(path)?;
    let mut indices = Vec::new();
    for line in text.lines() {
        for part in line
            .split('#')
            .next()
            .unwrap()
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
        {
            let j: usize = part.parse()?;
            if j == 0 || j >= variables {
                return Err(
                    format!("dynamic index {j} is outside the witness or is constant one").into(),
                );
            }
            indices.push(j);
        }
    }
    indices.sort_unstable();
    if indices.windows(2).any(|w| w[0] == w[1]) {
        return Err("duplicate dynamic index".into());
    }
    Ok(indices)
}

#[cfg(feature = "zkey-reader")]
fn read_proving_key(path: &str) -> AppResult<ProvingKey<Bn254>> {
    let mut reader = BufReader::new(fs::File::open(path)?);
    // ark-circom currently reads its own matrices as well; they assume appended
    // public rows and are discarded in favor of the permuted R1CS matrices.
    let (key, _matrices) = ark_circom::read_zkey(&mut reader)?;
    Ok(key)
}

#[cfg(not(feature = "zkey-reader"))]
fn read_proving_key(_path: &str) -> AppResult<ProvingKey<Bn254>> {
    Err("pack requires a build with --features zkey-reader".into())
}

fn run() -> AppResult<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("mask-rln") if args.len() == 5 => {
            let graph_bytes = fs::read(&args[2])?;
            let parsed = r1cs::R1cs::parse(&fs::read(&args[3])?)?;
            let indices = graph::rln_dynamic_indices(&graph_bytes,
                parsed.matrices.num_instance_variables + parsed.matrices.num_witness_variables)?;
            let mut output = create_new(&args[4])?;
            for j in &indices { writeln!(output, "{j}")?; }
            output.flush()?;
            println!("{} dynamic witness indices; graph_sha256={}", indices.len(), hash(&graph_bytes));
        }
        Some("permute") if args.len() == 6 || args.len() == 7 => {
            let original = fs::read(&args[2])?;
            let parsed = r1cs::R1cs::parse(&original)?;
            let indices = read_indices(&args[4], parsed.matrices.num_instance_variables + parsed.matrices.num_witness_variables)?;
            let graph_hash = if let Some(path) = args.get(6) {
                let graph = fs::read(path)?;
                if graph::rln_dynamic_indices(&graph, parsed.matrices.num_instance_variables + parsed.matrices.num_witness_variables)? != indices {
                    return Err("dynamic indices do not match the RLN graph dependency mask".into());
                }
                format!("\"{}\"", hash(&graph))
            } else { "null".to_string() };
            let mut mask = vec![false; parsed.matrices.num_instance_variables + parsed.matrices.num_witness_variables];
            for &j in &indices { mask[j] = true; }
            let result = permute_rows(&parsed.matrices, &mask).map_err(|e| format!("permutation failed: {e}"))?;
            let output = parsed.encode(&result.matrices)?;
            let metadata = format!("{{\n  \"format\": \"dynamic-groth16-permuted-r1cs-v1\",\n  \"input_sha256\": \"{}\",\n  \"r1cs_sha256\": \"{}\",\n  \"graph_sha256\": {},\n  \"domain_size\": {},\n  \"subgroup_size\": {},\n  \"dynamic_indices\": {:?},\n  \"public_rows\": \"included\"\n}}\n", hash(&original), hash(&output), graph_hash, result.domain_size, result.subgroup_size, indices);
            if Path::new(&args[3]).exists() || Path::new(&args[5]).exists() || args[3] == args[5] { return Err("output file already exists or output paths are identical".into()); }
            let mut r1cs_output = create_new(&args[3])?;
            r1cs_output.write_all(&output)?;
            r1cs_output.flush()?;
            let mut metadata_output = create_new(&args[5])?;
            metadata_output.write_all(metadata.as_bytes())?;
            metadata_output.flush()?;
            println!("domain N={}, subgroup K={}, dynamic variables={}", result.domain_size, result.subgroup_size, indices.len());
        }
        Some("pack") if args.len() == 5 => {
            let input = fs::read(&args[2])?;
            let parsed = r1cs::R1cs::parse(&input)?;
            let key = SerializableProvingKey(read_proving_key(&args[3])?);
            let m = &parsed.matrices;
            let variables = m.num_instance_variables + m.num_witness_variables;
            if !m.num_constraints.is_power_of_two() || key.0.h_query.len() != m.num_constraints
                || key.0.vk.gamma_abc_g1.len() != m.num_instance_variables
                || key.0.a_query.len() != variables || key.0.b_g1_query.len() != variables
                || key.0.b_g2_query.len() != variables || key.0.l_query.len() != m.num_witness_variables {
                return Err("key dimensions do not match the permuted Circom R1CS".into());
            }
            let mut output = create_new(&args[4])?;
            key.serialize_uncompressed(&mut output)?;
            SerializableMatrices::from(parsed.matrices).serialize_uncompressed(&mut output)?;
            output.flush()?;
            println!("packed complete permuted matrices; r1cs_sha256={}", hash(&input));
            eprintln!("Dimension checks do not prove that the key belongs to this R1CS; verify the zkey separately.");
        }
        Some("check-proof") if args.len() == 6 => {
            let mut source = BufReader::new(fs::File::open(&args[2])?);
            let pk = SerializableProvingKey::deserialize_uncompressed_unchecked(&mut source)?.0;
            let matrices: ConstraintMatrices<Fr> = SerializableMatrices::deserialize_uncompressed_unchecked(&mut source)?.into();
            let full = r1cs::read_witness(&fs::read(&args[3])?)?;
            let indices = read_indices(&args[4], full.len())?;
            let subgroup: usize = args[5].parse()?;
            let mut values: Vec<_> = full.iter().skip(1).copied().map(Some).collect();
            for j in indices { values[j - 1] = None; }
            let setup = Groth16DynamicV3::<Bn254, CircomIncluded>::setup(&pk, subgroup)?;
            let partial = Groth16DynamicV3::<Bn254, CircomIncluded>::preprocess(&pk, &matrices, &setup, &PartialAssignment::new(values))?;
            let (r, s) = (Fr::from(7), Fr::from(11));
            let proof = Groth16DynamicV3::<Bn254, CircomIncluded>::finish_with_randomness(&pk, &matrices, &setup, &full, r, s, &partial)?;
            let reference = ark_groth16::Groth16::<Bn254, CircomIncluded>::create_proof_with_reduction_and_matrices(
                &pk, r, s, &matrices, matrices.num_instance_variables, matrices.num_constraints, &full)?;
            if proof != reference || !ark_groth16::Groth16::<Bn254, CircomIncluded>::verify_proof(
                &ark_groth16::prepare_verifying_key(&pk.vk), &proof, &full[1..matrices.num_instance_variables])? {
                return Err("proof comparison or verification failed".into());
            }
            println!("v3 proof equals the ordinary proof and verifies (test-only deterministic randomness)");
        }
        Some("check-mask") if args.len() == 5 => {
            let first = r1cs::read_witness(&fs::read(&args[2])?)?;
            let second = r1cs::read_witness(&fs::read(&args[3])?)?;
            if first.len() != second.len() { return Err("witness lengths differ".into()); }
            let indices = read_indices(&args[4], first.len())?;
            let mut mask = vec![false; first.len()];
            for j in indices { mask[j] = true; }
            let changed: Vec<_> = first.iter().zip(&second).enumerate().filter_map(|(i, (a,b))| (a != b).then_some(i)).collect();
            if changed.iter().any(|&j| !mask[j]) { return Err("a witness value changed outside the dynamic mask".into()); }
            println!("{} changed witness entries are covered by the mask", changed.len());
        }
        _ => return Err("usage: r1cs-permute mask-rln <graph.bin> <input.r1cs> <indices.txt>\n       r1cs-permute permute <input.r1cs> <output.r1cs> <dynamic-indices.txt> <metadata.json> [rln-graph.bin]\n       r1cs-permute pack <permuted.r1cs> <input.zkey> <output.arkzkey>\n       r1cs-permute check-proof <packed.arkzkey> <witness.wtns> <indices.txt> <subgroup-size>\n       r1cs-permute check-mask <first.wtns> <second.wtns> <indices.txt>".into()),
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
