//! Minimal Circom R1CS v1 reader/writer for BN254, preserving wire labels.
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::ConstraintMatrices;
use std::io::{self, Cursor, Read};

type Row = Vec<(Fr, usize)>;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32_le(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn u64_le(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
fn bytes(r: &mut impl Read, n: usize) -> io::Result<Vec<u8>> {
    let mut b = vec![0; n];
    r.read_exact(&mut b)?;
    Ok(b)
}
fn u32_size(n: usize) -> io::Result<u32> {
    u32::try_from(n).map_err(|_| invalid("size exceeds R1CS u32 limit"))
}

pub struct R1cs {
    pub matrices: ConstraintMatrices<Fr>,
    sections: Vec<(u32, Vec<u8>)>,
    constraint_count_offset: usize,
}

impl R1cs {
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        let mut c = Cursor::new(data);
        if bytes(&mut c, 4)? != b"r1cs" || u32_le(&mut c)? != 1 {
            return Err(invalid("expected R1CS v1"));
        }
        let count = u32_le(&mut c)?;
        if count != 3 {
            return Err(invalid("expected only header, constraints, and wire-label sections; custom sections are unsupported"));
        }
        let mut sections = Vec::new();
        for _ in 0..count {
            let id = u32_le(&mut c)?;
            if !(1..=3).contains(&id) || sections.iter().any(|(other, _)| *other == id) {
                return Err(invalid("unknown or duplicate R1CS section"));
            }
            let len = usize::try_from(u64_le(&mut c)?).map_err(|_| invalid("section too large"))?;
            if len > data.len().saturating_sub(c.position() as usize) {
                return Err(invalid("truncated section"));
            }
            sections.push((id, bytes(&mut c, len)?));
        }
        if c.position() != data.len() as u64 {
            return Err(invalid("trailing R1CS data"));
        }
        let header = &sections
            .iter()
            .find(|(id, _)| *id == 1)
            .ok_or_else(|| invalid("missing header"))?
            .1;
        let mut h = Cursor::new(header);
        let width = u32_le(&mut h)? as usize;
        if width != 32 {
            return Err(invalid("only the 32-byte BN254 scalar field is supported"));
        }
        let modulus = bytes(&mut h, width)?;
        let mut expected = Fr::MODULUS.to_bytes_le();
        expected.resize(width, 0);
        if modulus != expected {
            return Err(invalid("R1CS scalar field is not BN254"));
        }
        let wires = u32_le(&mut h)? as usize;
        let outputs = u32_le(&mut h)? as usize;
        let inputs = u32_le(&mut h)? as usize;
        let _private_inputs = u32_le(&mut h)?;
        let _labels = u64_le(&mut h)?;
        let constraint_count_offset = h.position() as usize;
        let count = u32_le(&mut h)? as usize;
        if h.position() != header.len() as u64 {
            return Err(invalid("unexpected header length"));
        }
        let instances = outputs
            .checked_add(inputs)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| invalid("too many public variables"))?;
        if instances > wires {
            return Err(invalid("public variables exceed wire count"));
        }
        let labels = &sections
            .iter()
            .find(|(id, _)| *id == 3)
            .ok_or_else(|| invalid("missing wire labels"))?
            .1;
        if wires.checked_mul(8) != Some(labels.len()) {
            return Err(invalid("incorrect wire-label section length"));
        }
        let constraints = &sections
            .iter()
            .find(|(id, _)| *id == 2)
            .ok_or_else(|| invalid("missing constraints"))?
            .1;
        // Every constraint has at least three four-byte term counts.
        if count > constraints.len() / 12 {
            return Err(invalid("invalid constraint count"));
        }
        let mut r = Cursor::new(constraints);
        let mut a = Vec::with_capacity(count);
        let mut b = Vec::with_capacity(count);
        let mut c = Vec::with_capacity(count);
        for _ in 0..count {
            a.push(read_row(&mut r, wires)?);
            b.push(read_row(&mut r, wires)?);
            c.push(read_row(&mut r, wires)?);
        }
        if r.position() != constraints.len() as u64 {
            return Err(invalid("unexpected constraint data"));
        }
        let matrices = ConstraintMatrices {
            num_instance_variables: instances,
            num_witness_variables: wires - instances,
            num_constraints: count,
            a_num_non_zero: a.iter().map(Vec::len).sum(),
            b_num_non_zero: b.iter().map(Vec::len).sum(),
            c_num_non_zero: c.iter().map(Vec::len).sum(),
            a,
            b,
            c,
        };
        Ok(Self {
            matrices,
            sections,
            constraint_count_offset,
        })
    }

    pub fn encode(&self, m: &ConstraintMatrices<Fr>) -> io::Result<Vec<u8>> {
        if m.a.len() != m.num_constraints
            || m.b.len() != m.num_constraints
            || m.c.len() != m.num_constraints
            || m.num_instance_variables != self.matrices.num_instance_variables
            || m.num_witness_variables != self.matrices.num_witness_variables
        {
            return Err(invalid("invalid output matrices"));
        }
        let mut constraints = Vec::new();
        for i in 0..m.num_constraints {
            write_row(&mut constraints, &m.a[i])?;
            write_row(&mut constraints, &m.b[i])?;
            write_row(&mut constraints, &m.c[i])?;
        }
        let mut result = Vec::new();
        result.extend_from_slice(b"r1cs");
        result.extend_from_slice(&1u32.to_le_bytes());
        result.extend_from_slice(&3u32.to_le_bytes());
        for (id, original) in &self.sections {
            let mut data = original.clone();
            if *id == 1 {
                data[self.constraint_count_offset..self.constraint_count_offset + 4]
                    .copy_from_slice(&u32_size(m.num_constraints)?.to_le_bytes());
            }
            if *id == 2 {
                data = constraints.clone();
            }
            result.extend_from_slice(&id.to_le_bytes());
            result.extend_from_slice(&(data.len() as u64).to_le_bytes());
            result.extend_from_slice(&data);
        }
        Ok(result)
    }
}

fn read_row(r: &mut Cursor<&Vec<u8>>, wires: usize) -> io::Result<Row> {
    let count = u32_le(r)? as usize;
    let remaining = r.get_ref().len().saturating_sub(r.position() as usize);
    if count > remaining / 36 {
        return Err(invalid("truncated linear combination"));
    }
    let mut row = Vec::with_capacity(count);
    for _ in 0..count {
        let j = u32_le(r)? as usize;
        if j >= wires {
            return Err(invalid("wire index out of range"));
        }
        let raw = bytes(r, 32)?;
        let coefficient = Fr::from_le_bytes_mod_order(&raw);
        let mut canonical = coefficient.into_bigint().to_bytes_le();
        canonical.resize(32, 0);
        if canonical != raw {
            return Err(invalid("noncanonical field coefficient"));
        }
        row.push((coefficient, j));
    }
    Ok(row)
}
fn write_row(out: &mut Vec<u8>, row: &Row) -> io::Result<()> {
    out.extend_from_slice(&u32_size(row.len())?.to_le_bytes());
    for (coefficient, j) in row {
        out.extend_from_slice(&u32_size(*j)?.to_le_bytes());
        let mut bytes = coefficient.into_bigint().to_bytes_le();
        bytes.resize(32, 0);
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

/// Read a Circom witness file, checking its BN254 field and canonical values.
pub fn read_witness(data: &[u8]) -> io::Result<Vec<Fr>> {
    let mut cursor = Cursor::new(data);
    if bytes(&mut cursor, 4)? != b"wtns" || u32_le(&mut cursor)? != 2 || u32_le(&mut cursor)? != 2 {
        return Err(invalid("expected a Circom witness v2 file"));
    }
    let mut sections = Vec::new();
    for _ in 0..2 {
        let id = u32_le(&mut cursor)?;
        if !(1..=2).contains(&id) || sections.iter().any(|(other, _)| *other == id) {
            return Err(invalid("unknown or duplicate witness section"));
        }
        let len = usize::try_from(u64_le(&mut cursor)?)
            .map_err(|_| invalid("witness section too large"))?;
        if len > data.len().saturating_sub(cursor.position() as usize) {
            return Err(invalid("truncated witness section"));
        }
        sections.push((id, bytes(&mut cursor, len)?));
    }
    if cursor.position() != data.len() as u64 {
        return Err(invalid("trailing witness data"));
    }
    let header = &sections
        .iter()
        .find(|(id, _)| *id == 1)
        .ok_or_else(|| invalid("missing witness header"))?
        .1;
    let mut header = Cursor::new(header);
    if u32_le(&mut header)? != 32 {
        return Err(invalid("unsupported witness field size"));
    }
    let modulus = bytes(&mut header, 32)?;
    let mut expected = Fr::MODULUS.to_bytes_le();
    expected.resize(32, 0);
    if modulus != expected {
        return Err(invalid("witness field is not BN254"));
    }
    let count = u32_le(&mut header)? as usize;
    if header.position() != header.get_ref().len() as u64 {
        return Err(invalid("invalid witness header"));
    }
    let values = &sections
        .iter()
        .find(|(id, _)| *id == 2)
        .ok_or_else(|| invalid("missing witness values"))?
        .1;
    if count.checked_mul(32) != Some(values.len()) {
        return Err(invalid("invalid witness length"));
    }
    let mut result = Vec::with_capacity(count);
    for raw in values.chunks_exact(32) {
        let value = Fr::from_le_bytes_mod_order(raw);
        let mut canonical = value.into_bigint().to_bytes_le();
        canonical.resize(32, 0);
        if canonical != raw {
            return Err(invalid("noncanonical witness value"));
        }
        result.push(value);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::One;
    use dynamic_groth16::dynamic::v3::permutation::permute_rows;

    fn fixture() -> R1cs {
        let mut header = Vec::new();
        header.extend_from_slice(&32u32.to_le_bytes());
        let mut modulus = Fr::MODULUS.to_bytes_le();
        modulus.resize(32, 0);
        header.extend_from_slice(&modulus);
        for n in [3u32, 1, 0, 1] {
            header.extend_from_slice(&n.to_le_bytes());
        }
        header.extend_from_slice(&3u64.to_le_bytes());
        let count_offset = header.len();
        header.extend_from_slice(&1u32.to_le_bytes());
        let labels = (0u64..3).flat_map(u64::to_le_bytes).collect();
        let matrices = ConstraintMatrices {
            num_instance_variables: 2,
            num_witness_variables: 1,
            num_constraints: 1,
            a_num_non_zero: 1,
            b_num_non_zero: 1,
            c_num_non_zero: 1,
            a: vec![vec![(Fr::one(), 2)]],
            b: vec![vec![(Fr::one(), 2)]],
            c: vec![vec![(Fr::one(), 1)]],
        };
        R1cs {
            matrices,
            sections: vec![(1, header), (2, vec![]), (3, labels)],
            constraint_count_offset: count_offset,
        }
    }
    #[test]
    fn roundtrip_preserves_constraints_labels_and_permutation() {
        let original = fixture();
        let encoded = original.encode(&original.matrices).unwrap();
        let parsed = R1cs::parse(&encoded).unwrap();
        assert_eq!(parsed.matrices.a, original.matrices.a);
        assert_eq!(parsed.matrices.b, original.matrices.b);
        assert_eq!(parsed.matrices.c, original.matrices.c);
        let permuted = permute_rows(&parsed.matrices, &[false, true, true]).unwrap();
        let output = parsed.encode(&permuted.matrices).unwrap();
        let reread = R1cs::parse(&output).unwrap();
        assert_eq!(reread.matrices.a, permuted.matrices.a);
        assert_eq!(reread.matrices.b, permuted.matrices.b);
        assert_eq!(reread.matrices.c, permuted.matrices.c);
        assert_eq!(reread.sections[2].1, original.sections[2].1);
        assert_eq!(permuted.domain_size, 4);
    }
    #[test]
    fn rejects_truncated_and_unsupported_inputs() {
        let original = fixture();
        let mut encoded = original.encode(&original.matrices).unwrap();
        assert!(R1cs::parse(&encoded[..encoded.len() - 1]).is_err());
        encoded[8..12].copy_from_slice(&4u32.to_le_bytes());
        assert!(R1cs::parse(&encoded).is_err());
    }
}
