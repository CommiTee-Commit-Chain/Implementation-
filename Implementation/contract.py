from solc import compile_standard, compile_source
import json
from easysolc import Solc
solc = Solc()


def compile_source_file(file_path):
    with open(file_path, 'r') as f:
        source = f.read()

    return compile_source(source)


class Contract:

    def __init__(self, web3):
        contract_interface = solc.compile("contract.sol")['Plasma']
        self._abi = contract_interface['abi']
        self._bytecode = contract_interface['bytecode']
        self._web3 = web3
        self._address = ""

    def get_byte_code(self):
        return self._bytecode

    def get_abi(self):
        return self._abi

    def get_address(self):
        return self._address

    def deploy_contract(self):
        tmp_contract = self._web3.eth.contract(abi=self._abi, bytecode=self._bytecode)
        tx_hash = tmp_contract.constructor().transact()
        tx_receipt = self._web3.eth.waitForTransactionReceipt(tx_hash)
        self._address = tx_receipt.contractAddress
        contract = self._web3.eth.contract(address=self._address, abi=self._abi)
        return contract
