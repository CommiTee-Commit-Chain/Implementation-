# Plasma TEE Implementation

<h3> Underlying Test Blockchain

In order to run the python scripts you need to install Ganache CLI v6.9.1 (ganache-core: 2.10.2). 

Follow the instructions from the [ganache-cli repository](https://github.com/trufflesuite/ganache-cli)

<h3> Solidity Compiler

In order to install the required solidity compiler version run the following commands.

`$ wget https://github.com/ethereum/solidity/releases/download/v0.5.3/solc-static-linux`

`$ chmod +x ./solc-static-linux`

`$ sudo mv solc-static-linux /usr/bin/solc`

<h3> Python Dependencies

The repository is run on python 3.6. In order to install the required dependencies run the following command.

`$ pip install -r requirements.txt`

<h3> Starting The Underlying Blockchain

To start the simulated ganache-cli blockchain run the following command

`$ ganache-cli --acctKeys plasma-tee-implementation/acaccs.json -m 'testasdf'`

Run benchmarks via

`$ python benchmark.py`