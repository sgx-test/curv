pub mod pederson_hash;
pub mod pedersen_points;

use starknet_ff::FieldElement;
pub use pederson_hash::*;

pub fn hash_util(message: &[FieldElement]) -> FieldElement {
    let mut hash = FieldElement::ZERO;
    for x in message {
        hash = pedersen_hash(&hash, x);
    }
    hash = pedersen_hash(&hash, &FieldElement::from(message.len()));
    hash
}
