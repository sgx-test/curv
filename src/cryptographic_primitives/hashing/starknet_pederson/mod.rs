pub mod pederson_hash;
pub mod pedersen_points;

use starknet_ff::FieldElement;
pub use pederson_hash::*;

pub fn hash_util(message: &[FieldElement]) -> FieldElement {
    let mut hash = FieldElement::from_bytes_be(&[0u8; 32]).unwrap();
    for x in message {
        hash = pedersen_hash(x, &hash);
    }
    hash
}

#[test]
fn test_hash_util() {
    let mut message = vec![];
    message.push(FieldElement::from_bytes_be(&[1u8; 32]).unwrap());
    message.push(FieldElement::from_bytes_be(&[2u8; 32]).unwrap());
    message.push(FieldElement::from_bytes_be(&[3u8; 32]).unwrap());
    message.push(FieldElement::from_bytes_be(&[4u8; 32]).unwrap());

    assert_eq!(hex::encode(hash_util(&message).to_bytes_be()), "07e25573fbbd80e68b812e1e983f2b02b82dedb73746f75da20ea7b20c014e5f");
}
