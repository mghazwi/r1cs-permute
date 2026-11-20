use ark_bn254::{Bn254, Fr};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// Uncompressed key + matrices layout based on ark-zkey:
// https://github.com/seemenkina/ark-zkey/blob/029bfe80a5881c3ac4e746f051bf409f779b6458/src/lib.rs
// This is also the representation read by ZeroKit.
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SerializableProvingKey(pub ProvingKey<Bn254>);
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SerializableMatrix {
    data: Vec<Vec<(Fr, usize)>>,
}
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct SerializableMatrices {
    num_instance_variables: usize,
    num_witness_variables: usize,
    num_constraints: usize,
    a_num_non_zero: usize,
    b_num_non_zero: usize,
    c_num_non_zero: usize,
    a: SerializableMatrix,
    b: SerializableMatrix,
    c: SerializableMatrix,
}
impl From<ConstraintMatrices<Fr>> for SerializableMatrices {
    fn from(m: ConstraintMatrices<Fr>) -> Self {
        Self {
            num_instance_variables: m.num_instance_variables,
            num_witness_variables: m.num_witness_variables,
            num_constraints: m.num_constraints,
            a_num_non_zero: m.a_num_non_zero,
            b_num_non_zero: m.b_num_non_zero,
            c_num_non_zero: m.c_num_non_zero,
            a: SerializableMatrix { data: m.a },
            b: SerializableMatrix { data: m.b },
            c: SerializableMatrix { data: m.c },
        }
    }
}
impl From<SerializableMatrices> for ConstraintMatrices<Fr> {
    fn from(m: SerializableMatrices) -> Self {
        Self {
            num_instance_variables: m.num_instance_variables,
            num_witness_variables: m.num_witness_variables,
            num_constraints: m.num_constraints,
            a_num_non_zero: m.a_num_non_zero,
            b_num_non_zero: m.b_num_non_zero,
            c_num_non_zero: m.c_num_non_zero,
            a: m.a.data,
            b: m.b.data,
            c: m.c.data,
        }
    }
}
