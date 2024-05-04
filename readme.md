# Confidential Distributed Ledgers Scheme

## Introduction

We propose a new collaborative financial ledger for online syndicated lending. It leverages homomorphic encryption/commitment to allow the reuse of intermediary transactional
states without breaking the privacy promise during the full lifecycle of a loan. This system also supports efficient regulationcompliant auditing.

## Usage

First, please make sure that Rust is installed to run this program. If it is not installed, [click here](https://www.rust-lang.org/) to install.

Then download the dependencies and compile the source code.

```
cd Confidential Distributed Ledgers

cargo build
```
Configure the node address. If executing locally, no modifications are needed. Otherwise, modify the address to the actual address of each node.

The configuration file path is: 
```
./integration_test/src/regulagtor/config/config_file/reg_config.json //regulator configuration file
./integration_test/src/node/node*/config/config_file/node_config.json //node configuration file
```

### Start DKG(Distributed Key Generation))
```
//start regulator
cargo test --package intergration_test --lib -- regulator::regulator::test --exact --show-output
//start nodes
cargo test --package intergration_test --lib -- node::node1::node1::test --exact --show-output
cargo test --package intergration_test --lib -- node::node2::node2::test --exact --show-output
cargo test --package intergration_test --lib -- node::node3::node3::test --exact --show-output
cargo test --package intergration_test --lib -- node::node4::node4::test --exact --show-output 
```
The generated key pair will be written into file ./node/node*/keypair.txt.
### Start Distributed Ledgers
```
//start regulator
cargo test --package intergration_test --lib -- regulator::regulator::decrypt_test --exact --show-output
//start nodes
cargo test --package intergration_test --lib -- node::node1::node1::test_decrypt --exact --show-output 
cargo test --package intergration_test --lib -- node::node1::node1::test_decrypt --exact --show-output 
cargo test --package intergration_test --lib -- node::node3::node3::test_decrypt --exact --show-output
cargo test --package intergration_test --lib -- node::node4::node4::test_decrypt --exact --show-output
```
The calculation result is located at:./node/node*/log/node.log

## Comparison experiment
The comparison experiment is based on the Pedersen-VSS implementation. The project code is located in the Comparison Scheme. The running method is the same as that of Confidential Distributed Ledgers.
