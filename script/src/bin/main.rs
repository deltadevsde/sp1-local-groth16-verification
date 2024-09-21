//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use fibonacci_lib::PublicValuesStruct;
use gnark_bn254_verifier::Fr;
use num_bigint::BigUint;
use sp1_sdk::{ProverClient, SP1Proof, SP1Stdin};
use std::str::FromStr;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

    #[clap(long, default_value = "20")]
    n: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.n);

    println!("n: {}", args.n);

    if args.execute {
        // Execute the program
        let (output, report) = client.execute(FIBONACCI_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        let PublicValuesStruct { n, a, b } = decoded;
        println!("n: {}", n);
        println!("a: {}", a);
        println!("b: {}", b);

        let (expected_a, expected_b) = fibonacci_lib::fibonacci(n);
        assert_eq!(a, expected_a);
        assert_eq!(b, expected_b);
        println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // // Setup the program for proving.
        let (pk, _) = client.setup(FIBONACCI_ELF);

        // // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .expect("failed to generate proof");
        println!("Successfully generated proof!");

        // let proof = SP1ProofWithPublicValues::load("/Users/distractedm1nd/proof.bin").unwrap();
        let vk =
            std::fs::read("/Users/distractedm1nd/.sp1/circuits/v3.0.0-rc1/groth16_vk.bin").unwrap();

        if let SP1Proof::Groth16(groth16_proof) = proof.proof {
            dbg!(&groth16_proof.encoded_proof);
            let raw_proof = hex::decode(&groth16_proof.encoded_proof).unwrap();

            let vkey_hash = BigUint::from_str(&groth16_proof.public_inputs[0]).unwrap();
            let committed_values_digest =
                BigUint::from_str(&groth16_proof.public_inputs[1]).unwrap();

            let pub_inputs = &[Fr::from(vkey_hash), Fr::from(committed_values_digest)];

            let res = gnark_bn254_verifier::verify(
                &raw_proof,
                &vk,
                pub_inputs,
                gnark_bn254_verifier::ProvingSystem::Groth16,
            );

            assert!(res)
        } else {
            panic!("wtf?");
        }

        // Verify the proof.
        // client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
    }
}
