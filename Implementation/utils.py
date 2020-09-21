from eth_utils import to_hex, to_bytes
from web3 import Web3


class plasma_transaction:
    _sender: str
    _receiver: str
    _value: int
    _index: int

    def __init__(self, sender, receiver, value, index):
        self._sender = sender
        self._receiver = receiver
        self._value = value
        self._index = index


def str_to_hex(hex_string):
    hex_int = int(hex_string, base=16)
    new_int = hex_int + 0x200
    return hex_int.to_bytes(20, 'big')


def prep_chain_tx_send_data(tx):
    write_data = {"hash": to_hex(tx["hash"]),
                  "blockHash": to_hex(tx["blockHash"]),
                  "nonce": tx["nonce"],
                  "gasPrice": tx["gasPrice"],
                  "gas": tx["gas"],
                  "to": tx["to"],
                  "value": tx["value"],
                  "input": tx["input"],
                  "v": tx["v"],
                  "r": Web3.toInt(tx["r"]),
                  "s": Web3.toInt(tx["s"])
                  }
    return write_data


def prep_block_send_data(block):
    write_data = {"hash": to_hex(block["hash"]),
              "parentHash": to_hex(block["parentHash"]),
              "sha3Uncles": to_hex(block["sha3Uncles"]),
              "miner": to_hex(str_to_hex(block["miner"])),
              "stateRoot": to_hex(block["stateRoot"]),
              "transactionsRoot": to_hex(block["transactionsRoot"]),
              "receiptsRoot": to_hex(block["receiptsRoot"]),
              "logsBloom": Web3.toInt(block["logsBloom"]),
              "difficulty": block["difficulty"],
              "number": block["number"],
              "gasLimit": block["gasLimit"],
              "gasUsed": block["gasUsed"],
              "timestamp": block["timestamp"],
              "extraData": to_hex(block["extraData"]),
              "mixHash": to_hex(block["mixHash"]),
              "nonce": to_hex(block["nonce"])
              }
    return write_data


def to_32byte_hex(val):
    return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))


def prep_signature_for_solidity(signed_message):
    ec_recover_args = (msghash, v, r, s) = (Web3.toHex(signed_message.messageHash), signed_message.v,
                                            to_32byte_hex(signed_message.r), to_32byte_hex(signed_message.s),)
    return ec_recover_args


def signature_from_hex_to_solidity(hexstr):
    sig = Web3.toBytes(hexstr=hexstr)
    v, hex_r, hex_s = Web3.toInt(sig[-1]), Web3.toHex(sig[:32]), Web3.toHex(sig[32:64])
    return v, hex_r, hex_s


def signature_from_solidity_to_hex(v, r, s):
    return Web3.toHex(r) + Web3.toHex(s)[2:] + Web3.toHex(v)[2:]
