import os
import sys
scriptpath = "../"
sys.path.append(os.path.abspath(scriptpath))
from typing import Dict, List, Tuple
from web3 import Web3
from eth_utils import to_bytes, to_hex
from eth_utils import keccak
from web3 import Web3
from eth_account.messages import encode_defunct
from eth_account import Account
import sha3
import socket
import random
import string
import rlp
import json
from rlp.sedes import (
    BigEndianInt,
    big_endian_int,
    Binary,
    binary,
)
# Signatures on uppercase addresses for exits to match formats
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65433  # Port to listen on (non-privileged ports are > 1023)
address = Binary.fixed_length(20, allow_empty=True)
hash32 = Binary.fixed_length(32)
int256 = BigEndianInt(256)
trie_root = Binary.fixed_length(32, allow_empty=True)
w3 = Web3(None,None,None)
"""
First we define the methods to calculate the root hash
Code from https://ethereum-classic-guide.readthedocs.io/en/latest/docs/appendices/root_hashes.html
"""
HASH_LEN = 32
HEXADEC  = 16


def remove(dict_, segment):
        """
        Removes initial key segments from the keys of dictionaries.
        """

        return {k[len(segment):] : v for k, v in dict_.items()}


def select(dict_, segment):
        """
        Selects dictionary elements with given initial key segments.
        """

        return {k : v for k, v in dict_.items() if k.startswith(segment)}


def find(dict_):
        """
        Finds common initial segments in the keys of dictionaries.
        """

        segment = ""
        for i in range(min([len(e) for e in dict_.keys()])):
                if len({e[i] for e in dict_.keys()}) > 1:
                        break
                segment += list(dict_.keys())[0][i]

        return segment


def patricia_r(dict_):
        """
        Creates Patricia tries that begin with regular nodes.
        """

        pt = (HEXADEC + 1) * [None]
        if "" in dict_:
                pt[-1] = dict_[""]
                del(dict_[""])
        for e in {e[0] for e in dict_.keys()}:
                pt[int(e, HEXADEC)] = patricia(remove(select(dict_, e), e))

        return pt


def patricia_s(dict_):
        """
        Creates Patricia tries composed of one key ending special node.
        """

        pt = list(dict_.items())[0]
        if len(pt[0]) % 2 == 0:
                pt = (bytes.fromhex("20" + pt[0]), pt[1])
        else:
                pt = (bytes.fromhex("3"  + pt[0]), pt[1])

        return pt


def patricia(dict_):
        """
        Creates Patricia tries from dictionaries.
        """

        segment = find(dict_)
        if   len(dict_) == 1:
                pt = patricia_s(dict_)
        elif segment:
                dict_ = remove(dict_, segment)
                if len(segment) % 2 == 0:
                        pt = [bytes.fromhex("00" + segment), patricia_r(dict_)]
                else:
                        pt = [bytes.fromhex("1"  + segment), patricia_r(dict_)]
        else:
                pt = patricia_r(dict_)

        return pt


def merkle(element):
        """
        Encodes Patricia trie elements using Keccak 256 hashes and RLP.
        """

        if   not element:
                merkle_ = b""
        elif isinstance(element, str):
                merkle_ = bytes.fromhex(element)
        elif isinstance(element, bytes):
                merkle_ = element
        else:
                merkle_ = [merkle(e) for e in element]
                rlp_    = rlp.encode(merkle_)
                if len(rlp_) >= HASH_LEN:
                        merkle_ = sha3.keccak_256(rlp_).digest()

        return merkle_


def merkle_patricia(dict_):
        """
        Creates Merkle Patricia tries from dictionaries.
        """

        return [merkle(e) for e in patricia(dict_)]


def root_hash(dict_):
        """
        Calculates root hashes of Merkle Patricia tries from dictionaries.
        """

        dict_ = {k.hex() : v for k, v in dict_.items()}

        return sha3.keccak_256(rlp.encode(merkle_patricia(dict_))).hexdigest()


"""
Helper function for conversion
"""


def str_to_hex(hex_string):
    hex_int = int(hex_string, base=16)
    return hex_int.to_bytes(20, 'big')


"""
Transaction Header Class used to ensure correct tx hash
"""


class TransactionHeader(rlp.Serializable):
    fields = [
        ('nonce', big_endian_int),
        ('gasPrice', big_endian_int),
        ('gas', big_endian_int),
        ('to', address),
        ('value', big_endian_int),
        ('input', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int)
    ]

    def hash(self) -> bytes:
        return keccak(rlp.encode(self))


"""
Block Header class to ensure correct block hash
"""


class BlockHeader(rlp.Serializable):
    fields = [
        ('parent_hash', hash32),
        ('uncles_hash', hash32),
        ('coinbase', address),
        ('state_root', trie_root),
        ('transaction_root', trie_root),
        ('receipt_root', trie_root),
        ('bloom', int256),
        ('difficulty', big_endian_int),
        ('block_number', big_endian_int),
        ('gas_limit', big_endian_int),
        ('gas_used', big_endian_int),
        ('timestamp', big_endian_int),
        ('extra_data', binary),
        ('mix_hash', binary),
        ('nonce', Binary(8, allow_empty=True))
    ]

    def hash(self) -> bytes:
        return keccak(rlp.encode(self))


"""
Helper function for conversion
"""


def int_to_bytes(number):
    if number:
        hex_ = hex(number)[2:]
        if len(hex_) % 2 != 0:
            hex_ = "0" + hex_
        result = bytes.fromhex(hex_)
    else:
        result = b""

    return result


"""
The enclave class, implementing the pseudo code from the paper
"""


class Enclave:
    _msk: str
    _mpk: str
    _private_key: str
    _public_key: str
    _balances: Dict[str, int]
    _total_deposits: Dict[str, int]
    _deposits: List[Tuple[str, str, int]]
    _transactions: Dict[str, List[Tuple[str, str, int]]]
    _set_of_parties: List[str]
    _status: int
    _index: int
    _sec_param: int

    def __init__(self, msk, mpk, block, abi, contract_address):
        self._status = 0
        self._msk = msk
        self._mpk = mpk
        self._checkpoint = block
        self._contract = w3.eth.contract(address=contract_address, abi=abi)
        self._sec_param = 0

    @classmethod
    def __verify_transaction_hash(cls, transaction):
        header = TransactionHeader(nonce=transaction["nonce"],
                                   gasPrice=transaction["gasPrice"],
                                   gas=transaction["gas"],
                                   to=to_bytes(hexstr=transaction["to"]),
                                   value=transaction["value"],
                                   input=to_bytes(hexstr=transaction["input"]),
                                   v=transaction["v"],
                                   r=transaction["r"],
                                   s=transaction["s"]
                                   )
        if to_hex(header.hash()) == transaction["hash"]:
            return True
        else:
            return False

    @classmethod
    def __verify_block_hash(cls, block):
        header = BlockHeader(parent_hash=to_bytes(hexstr=block["parentHash"]),
                             uncles_hash=to_bytes(hexstr=block["sha3Uncles"]),
                             coinbase=to_bytes(hexstr=block["miner"]),
                             state_root=to_bytes(hexstr=block["stateRoot"]),
                             transaction_root=to_bytes(hexstr=block["transactionsRoot"]),
                             receipt_root=to_bytes(hexstr=block["receiptsRoot"]),
                             bloom=block["logsBloom"],
                             difficulty=block["difficulty"],
                             block_number=block["number"],
                             gas_limit=block["gasLimit"],
                             gas_used=block["gasUsed"],
                             timestamp=block["timestamp"],
                             extra_data=to_bytes(hexstr=block["extraData"]),
                             mix_hash=to_bytes(hexstr=block["mixHash"]),
                             nonce=to_bytes(hexstr=block["nonce"])
                             )
        if to_hex(header.hash()) == block["hash"]:
            return True
        else:
            return False

    @classmethod
    def __verify_chain(cls, chain, checkpoint):
        result = True
        for i,block in enumerate(chain):
            if not cls.__verify_block_hash(block):
                result = False
            if i == 0 and block["parentHash"] != checkpoint["hash"]:
                result = False
            elif i > 0 and block["parentHash"] != chain[i-1]["hash"]:
                result = False
        return result

    @classmethod
    def __signature_from_solidity_to_hex(cls, v, r, s):
        return Web3.toHex(r) + Web3.toHex(s)[2:] + Web3.toHex(v)[2:]

    def __verify_signature(self, signature, msg):
        signature_bytes = to_bytes(hexstr=signature)
        encoding = encode_defunct(text=msg)
        signer = w3.eth.account.recover_message(encoding, signature=signature_bytes)
        return self._public_key == signer

    @classmethod
    def __gen_random_string(cls, length: int):
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for i in range(length))

    @classmethod
    def __verify_deposit_transaction(cls, block, transaction, contract):
        """
        Verify if tx called deposit in block
        :param block:
        :param transaction:
        :param contract:
        :return:
        """
        if block["hash"] != transaction["blockHash"]:
            return None
        input = contract.decode_function_input(transaction["input"])
        if input[0].fn_name != "deposit":
            return None
        return input[1]["p"]

    def __verify_exits_transaction(self, block, transaction, contract):
        """
        Verify if exit was started successfully
        :param block: Block where exit was started
        :param transaction: Transaction that was sent
        :param contract:
        :return: Party that exited or None
        """
        if block["hash"] != transaction["blockHash"]:
            return None
        input = contract.decode_function_input(transaction["input"])
        if input[0].fn_name != "exit":
            return None
        input = input[1]
        test_sig = self.__signature_from_solidity_to_hex(input["v_b"], input["r_b"], input["s_b"])
        if self.__verify_signature(test_sig, str(self._index) + "|" + str(input["balance"])):
            return transaction['from']
        else:
            return None

    @classmethod
    def __verify_exits_finalized(cls, _transactions, contract):
        """
        Verify if exits were finalized
        :param _transactions: transaction list
        :param contract:
        :return: True or False
        """
        for transaction in _transactions:
            input = contract.decode_function_input(transaction["input"])
            if input[0].fn_name == "finalizeExits":
                return True
        return False

    def verify_transactions(self, transactions, block):
        """
        Verify if  given transactions are part of the given block
        :param transactions:
        :param block:
        :return: True or False
        """
        trasn_dict = dict()
        for i, data in enumerate(transactions):
            v = [int_to_bytes(data["nonce"]),
                 int_to_bytes(data["gasPrice"]),
                 int_to_bytes(data["gas"]),
                 to_bytes(hexstr=data["to"]),
                 int_to_bytes(data["value"]),
                 to_bytes(hexstr=data["input"]),
                 int_to_bytes(data["v"]),
                 int_to_bytes(data["r"]),
                 int_to_bytes(data["s"])]
            k = rlp.encode(int_to_bytes(i))
            trasn_dict[k] = rlp.encode(v)
        calc_hash = root_hash(trasn_dict)
        return "0x" + calc_hash == block["transactionsRoot"]

    def get_public_key(self):
        return self._public_key

    def get_index(self):
        return self._index

    def gen_keys(self):
        """
        Initialize values and generate keypair
        """
        if self._status == 0:
            acct = Account.create(self.__gen_random_string(10))
            self._private_key = to_hex(acct.privateKey)
            print(self._private_key)
            self._public_key = acct.address
            self._balances = dict()
            self._total_deposits = dict()
            self._deposits = []
            self._transactions = dict()
            self._set_of_parties = []
            self._set_of_parties.append("0xDaa4599e4F584816CE665f7D3A89F020d12541A6")
            self._balances["0xDaa4599e4F584816CE665f7D3A89F020d12541A6"] = 0
            self._index = 0
            self._status += 1
            self._tx_queue = []

    def process_deposits(self, chain, _transactions):
        """
        Process deposits
        :param chain: chain confirming deposit
        :param _transactions: transactions of each block
        :return: None
        """
        chain_verif = self.__verify_chain(chain, self._checkpoint)
        if not chain_verif:
            return None
        if len(_transactions) != len(chain):
            return None
        deposits = []
        for i, transactions in enumerate(_transactions):
            if not self.verify_transactions(transactions, chain[i]):
                return None
            for transaction in transactions:
                out = self.__verify_deposit_transaction(chain[i], transaction, self._contract)
                if out and (transaction["hash"], out, transaction["value"]) not in self._deposits:
                    b = self._balances.get(out, 0)
                    self._balances[out] = b + transaction["value"]
                    dep = self._total_deposits.get(out, 0)
                    self._total_deposits[out] = dep + transaction["value"]
                    result_string = "deposited, " + out + ", " + str(transaction["value"])
                    deposits.append((result_string, to_hex(w3.eth.account.sign_message(
                    encode_defunct(text=result_string), private_key=self._private_key).signature)))
                    if out not in self._set_of_parties:
                        self._set_of_parties.append(out)
        self._checkpoint = chain[-1]
        return None

    def collect_transaction(self, transaction_dump, signature):
        """
        Add transactions to queue of tx to be processed
        :param transaction_dump: json dump of transaction
        :param signature: signature of tx
        """
        self._tx_queue.append((transaction_dump, signature))

    def process_tx(self):
        """
        Processing transactions and finalize epoch
        :return: finalization and balance values
        """
        for transaction_dump, signature in self._tx_queue:
            transaction = json.loads(transaction_dump)
            signature_bytes = to_bytes(hexstr=signature)
            encoding = encode_defunct(text=transaction_dump)
            sender = transaction["sender"]
            receiver = transaction["receiver"]
            value = transaction["value"]
            index = transaction["index"]
            signer = w3.eth.account.recover_message(encoding, signature=signature_bytes)
            if self._index != index or signer != sender or self._balances.get(sender, 0) < value\
                    or (sender, receiver, value) in self._transactions.get(sender, []):
                x = 0
            else:
                tx_sender = self._transactions.get(sender, [])
                if tx_sender:
                    self._transactions[sender] = tx_sender.append((sender, receiver, value))
                else:
                    self._transactions[sender] = [(sender, receiver, value)]
                tx_receiver = self._transactions.get(receiver, [])
                if tx_receiver:
                    self._transactions[receiver] = tx_receiver.append((sender, receiver, value))
                else:
                    self._transactions[receiver] = [(sender, receiver, value)]
                self._balances[sender] = self._balances.get(sender, 0)-value
                self._balances[receiver] = self._balances.get(receiver,0)+value
        return self.finalize()

    def process_exits(self, chain, _transactions):
        """

        :param chain: chain with exits and confirming blocks
        :param _transactions: transactions of each block for recalculation
        :return:
        """
        if len(_transactions) != len(chain):
            return None
        chain_verif = self.__verify_chain(chain, self._checkpoint)
        if not chain_verif:
            return None
        # len - k
        if not self.__verify_exits_finalized(_transactions[len(chain)-self._sec_param-1], self._contract):
            return None
        for i, transactions in enumerate(_transactions):
            if not self.verify_transactions(transactions, chain[i]):
                return None
            for transaction in transactions:
                party = self.__verify_exits_transaction(chain[i], transaction, self._contract)
                if party:
                    self._balances[party] = 0
                    self._set_of_parties.remove(party)
        return "exits_processed"

    def finalize(self):
        """
        Finalization of the epoch
        :return: signed finalization and balance values
        """
        self._index = self._index + 1
        sigma_E_msg = "updated|" + str(self._index)
        sigma_E = w3.eth.account.sign_message(encode_defunct(text=sigma_E_msg), private_key=self._private_key)
        balance_result = dict()
        for p_i in self._set_of_parties:
            b_e = self._balances[p_i]
            msg = str(self._index) + "|" + str(b_e) + "|0x" + str.upper(p_i[2:])
            sigma_i = to_hex(w3.eth.account.sign_message(encode_defunct(text=msg),
                                                         private_key=self._private_key).signature)
            balance_result[p_i] = (msg, sigma_i)
        self._transactions.clear()
        self._total_deposits.clear()
        self._tx_queue.clear()
        return sigma_E_msg, to_hex(sigma_E.signature), balance_result


def init_enclave(block, abi, contract_address):
    """

    :param block: checkpoint block
    :param abi: contract abi
    :param contract_address: contract address
    :return: enclave instance
    """
    enclave = Enclave(" ", " ", block, abi, contract_address)
    enclave.gen_keys()
    return enclave


"""
Server used to receive function calls by the operator via sockets
Function calls consist of the function name, parameters and a signature where the last two are optional
"""


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        state = 0
        while True:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr[0])
                while True:
                    data = conn.recv(12288)
                    if not data:
                        break
                    json_data = json.loads(data)
                    function_name = json_data["fname"]
                    parameters = json_data["parameters"]
                    signature = json_data["signature"]
                    result = ""
                    if function_name == "init_enclave" and state == 0:
                        state = 1
                        enclave = init_enclave(parameters[0], parameters[1], parameters[2])
                        result = [enclave.get_public_key(), enclave.get_index()]
                    elif function_name == "process_deposit" and state == 1:
                        result = enclave.process_deposits(parameters[0], parameters[1])
                    elif function_name == "process_tx" and state == 1:
                        print("process_tx")
                        enclave.collect_transaction(json.dumps(parameters), signature)
                        result = "tx_included"
                    elif function_name == "process_exit" and state == 1:
                        result = enclave.process_exits(parameters[0], parameters[1])
                    elif function_name == "finalize_transactions" and state == 1:
                        result = enclave.process_tx()

                    conn.sendall(to_bytes(text=json.dumps(result)))


if __name__ == "__main__":
    run_server()

