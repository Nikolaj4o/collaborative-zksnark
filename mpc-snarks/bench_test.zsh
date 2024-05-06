set -xe

cargo build --release --bin proof

BIN=./target/release/proof

# BIN=$BIN ./scripts/bench.zsh marlin local 10 2
# BIN=$BIN ./scripts/bench.zsh marlin spdz 10 2
# BIN=$BIN ./scripts/bench.zsh marlin gsz 10 3
#./scripts/bench.zsh groth16 ark-local 10 2
#./scripts/bench.zsh groth16 hbc 10 2
BIN=$BIN ./scripts/bench.zsh groth16 local 10 2 shallownet
BIN=$BIN ./scripts/bench.zsh groth16 spdz 10 2 shallownet
BIN=$BIN ./scripts/bench.zsh groth16 local 10 2 cifar
BIN=$BIN ./scripts/bench.zsh groth16 spdz 10 2 cifar
BIN=$BIN ./scripts/bench.zsh groth16 local 10 2 face
BIN=$BIN ./scripts/bench.zsh groth16 spdz 10 2 face
#BIN=$BIN ./scripts/bench.zsh groth16 gsz 10 3
#BIN=$BIN ./scripts/bench.zsh marlin hbc 10 2
#BIN=$BIN ./scripts/bench.zsh plonk local 10 2
#BIN=$BIN ./scripts/bench.zsh plonk hbc 10 2
#BIN=$BIN ./scripts/bench.zsh plonk spdz 10 2
