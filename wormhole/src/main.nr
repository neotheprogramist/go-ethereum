fn main(preimage: [u8; 32], image: pub [u8; 32]) {
    let hash = std::hash::keccak256(preimage, 32);
    assert(hash == image);
}

#[test]
fn test_main() {
    let preimage = [
        198, 120, 134, 199, 115, 107, 39, 233, 189, 214, 107, 169, 105, 86, 33, 192, 6, 71, 26, 29,
        239, 72, 59, 222, 9, 255, 131, 33, 100, 64, 57, 178,
    ];

    // Calculate the expected hash for verification
    let expected_hash = [
        156, 231, 7, 109, 219, 140, 117, 212, 236, 4, 167, 85, 76, 83, 14, 31, 184, 96, 188, 135,
        220, 30, 111, 119, 23, 36, 57, 28, 167, 30, 69, 15,
    ];

    main(preimage, expected_hash);
}
