use std::io::{self, Read, Write};
use zerokernel_zk_guest::{run_zk_circuit_with_merkle, ZkCircuitInput};

fn main() {
    let mut stdin_buffer = Vec::new();
    if io::stdin().read_to_end(&mut stdin_buffer).is_ok() && !stdin_buffer.is_empty() {
        if let Ok(input) = bincode::deserialize::<ZkCircuitInput>(&stdin_buffer) {
            let output = run_zk_circuit_with_merkle(&input.policy, &input.events);
            if let Ok(encoded) = bincode::serialize(&output) {
                let _ = io::stdout().write_all(&encoded);
                return;
            }
        }
    }

    println!("zerokernel-zk-guest: pure RISC-V 32IM zero-knowledge kernel audit circuit ready.");
}
