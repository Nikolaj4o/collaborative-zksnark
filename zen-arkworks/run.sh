# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# sudo apt-get update
# sudo apt-get install cargo



#cargo run --example shallownet_poseidon --release > shallownet.log
#cargo run --example shallownet_poly --release > shallownet_poly_new.log
#cargo run --example shallownet_poseidon --release > shallownet_1.log
#cargo run --example shallownet_poly --release > shallownet_poly.log
#cargo run --example lenet_small_cifar_poseidon --release > lenet_small_cifar.log
#cargo run --example lenet_small_cifar_poseidon --release > lenet_small_cifar_1.log
cargo run --example lenet_small_cifar_poly --release > lenet_small_cifar_poly_new.log
#cargo run --example lenet_medium_cifar_poly --release > lenet_medium_cifar_poly.log
#cargo run --example lenet_medium_cifar_poseidon --release > lenet_medium_cifar.log
#cargo run --example lenet_medium_cifar_poseidon --release > lenet_medium_cifar_1.log
#cargo run --example lenet_large_cifar_poseidon --release > lenet_large_face.log
cargo run --example lenet_small_face_poly --release > lenet_small_face_poly_new.log
#cargo run --example lenet_medium_face_poly --release > lenet_medium_face_poly.log
#cargo run --example lenet_small_face_poseidon --release > lenet_small_face.log
#cargo run --example lenet_small_face_poseidon --release > lenet_small_face_1.log
#cargo run --example lenet_medium_face_poseidon --release > lenet_medium_face.log
#cargo run --example lenet_large_face_poseidon --release > lenet_large_face.log
