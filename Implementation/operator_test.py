import os
import sys
scriptpath = "../"
sys.path.append(os.path.abspath(scriptpath))
import socket
from eth_utils import to_bytes, to_hex
import json
from eth_account.messages import encode_defunct
from web3.auto import w3
from web3 import HTTPProvider
from web3 import Web3
import contract
import utils

"""
Test operator to test the enclave
"""
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65433        # The port used by the server
PORT_SERVER = 65434

pk_1 = "0x49079aF95b9F45BdAcEc269f49BdC5F6185C2B44"
sk_1 = "14b4e69dbcd3d069c835429e974ada13e4bd39c1debd1d7480bb0dbb07691a34"
pk_2 = "0xDaa4599e4F584816CE665f7D3A89F020d12541A6"
sk_2 = "0x2ce321bb3db167317a1f7c72fd7e4ab8b823734dd81d3d363acc1572767d8707"

# In order to use the fixed values for testing run the local chain via
# ganache-cli -m 'testasdf'


def str_to_hex(hex_string):
    hex_int = int(hex_string, base=16)
    new_int = hex_int + 0x200
    return hex_int.to_bytes(20,'big')


def create_transaction_request(v, i):
    transaction = {"sender": pk_1,
                   "receiver": pk_2,
                   "value": v,
                   "index": i}
    secret_key = sk_1
    tx_dump = json.dumps(transaction)
    signed_message = w3.eth.account.sign_message(encode_defunct(text=tx_dump), private_key=secret_key)
    call_process_tx = {"fname": "process_tx",
                       "parameters": {"sender": pk_1,
                                      "receiver": pk_2,
                                      "value": v,
                                      "index": i},
                       "signature": to_hex(signed_message.signature)
                       }

    tx_dump = json.dumps(call_process_tx)
    return tx_dump


def exit_on_contract(party, balance, balance_sig, start_exit_filter, exits_finalized_filter):
    v, r , s = utils.signature_from_hex_to_solidity(balance_sig)
    contr.functions.exit(party, balance, v, r, s).transact()
    transactions = []
    chain = []
    while True:
        event = start_exit_filter.get_new_entries()
        if event:
            block = web3.eth.getBlock(4)
            chain.append(block)
            block = web3.eth.getBlock(4, True)
            # tx = web3.eth.getTransaction(block["transactions"][0])
            tx = block["transactions"]
            transactions.append(tx)
            block = web3.eth.getBlock("latest")
            chain.append(block)
            block = web3.eth.getBlock("latest", True)
            # tx = web3.eth.getTransaction(block["transactions"][0])
            tx = block["transactions"]
            transactions.append(tx)
            break
    contr.functions.finalizeExits().transact()
    while True:
        event = exits_finalized_filter.get_new_entries()
        if event:
            block = web3.eth.getBlock("latest")
            chain.append(block)
            block = web3.eth.getBlock("latest", True)
            # tx = web3.eth.getTransaction(block["transactions"][0])
            tx = block["transactions"]
            transactions.append(tx)
            break
    return transactions, chain


def create_exit_request(chain, transactions):
    chain2 = []
    transactions2 = []
    for i, block in enumerate(chain):
        write_date = utils.prep_block_send_data(block)
        chain2.append(write_date)
        tmp = []
        for tx in transactions[i]:
            tmp.append(utils.prep_chain_tx_send_data(tx))
        transactions2.append(tmp)
    result = {"fname": "process_exit",
              "parameters": [chain2, transactions2],
              "signature": ""}
    return json.dumps(result)


def create_finalize_request():
    result = {"fname": "finalize_transactions",
              "parameters": "",
              "signature": ""}
    return json.dumps(result)


def create_enclave_initialization(block, abi, address):
    dump_data = []
    write_data = utils.prep_block_send_data(block)
    dump_data.append(write_data)
    dump_data.append(abi)
    dump_data.append(address)
    result = {"fname": "init_enclave",
              "parameters": dump_data,
              "signature": ""}
    return json.dumps(result)


def deposit_on_contract(contr, deposit_filter):

    contr.functions.deposit(accounts[0]).transact({"value": 10})
    chain = []
    transactions = []
    while True:
        event = deposit_filter.get_new_entries()
        test = deposit_filter.get_all_entries()
        if event:
            # Block 2 hardcoded to include initialization block
            block = web3.eth.getBlock(2)
            chain.append(block)
            block = web3.eth.getBlock(2, True)
            tx = block["transactions"]
            transactions.append(tx)
            block = web3.eth.getBlock("latest")
            chain.append(block)
            block = web3.eth.getBlock("latest", True)
            tx = block["transactions"]
            transactions.append(tx)
            break
    return transactions, chain


def create_deposit_request(chain, transactions):
    chain2 = []
    transactions2 = []
    for i, block in enumerate(chain):
        write_date = utils.prep_block_send_data(block)
        chain2.append(write_date)
        tmp = []
        for tx in transactions[i]:
            tmp.append(utils.prep_chain_tx_send_data(tx))
        transactions2.append(tmp)
    result = {"fname": "process_deposit",
              "parameters": [chain2, transactions2],
              "signature": ""}
    return json.dumps(result)


def finalize_on_contract(contr, finalize_sig, finalization_filter):
    v, r, s = utils.signature_from_hex_to_solidity(finalize_sig)
    contr.functions.finalize(v, r, s).transact()
    while True:
        event = finalization_filter.get_new_entries()
        if event:
            print("finalized on contract")
            break


web3 = Web3(HTTPProvider('http://localhost:8545'))
accounts = web3.eth.accounts
web3.eth.defaultAccount = accounts[0]
plasma_contract = contract.Contract(web3)
contr = plasma_contract.deploy_contract()
block_init = web3.eth.getBlock("latest")
deposit_filter = contr.events.Deposit.createFilter(fromBlock='latest')
finalization_filter = contr.events.Finalization.createFilter(fromBlock='latest')
start_exit_filter = contr.events.ExitStart.createFilter(fromBlock='latest')
exits_finalized_filter = contr.events.ExitsFinalized.createFilter(fromBlock='latest')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Requesting Enclave initialization")
    s.sendall(to_bytes(text=create_enclave_initialization(block_init, plasma_contract.get_abi(),
                                                           plasma_contract.get_address())))
    data = s.recv(1024)
    json_data = json.loads(data)
    enclave_key = json_data[0]
    index = json_data[1]
    print('Received the Enclave Public Key: ', json.loads(data))
    contr.functions.set_enclave(enclave_key).transact()

    print("Requesting Deposit of 10 for", accounts[0])
    transactions, chain = deposit_on_contract(contr, deposit_filter)
    s.sendall(to_bytes(text=create_deposit_request(chain, transactions)))
    data = s.recv(1024)
    print("Requesting Transaction from 0x49079aF95b9F45BdAcEc269f49BdC5F6185C2B44 "
           "to 0xdaa4599e4f584816ce665f7d3a89f020d12541a6")
    s.sendall(to_bytes(text=create_transaction_request(1,0)))
    data = s.recv(1024)
    json_data = json.loads(data)
    print('Received Answer to submitted transaction', json.loads(data))
    print("Requesting finalization")
    s.sendall(to_bytes(text=create_finalize_request()))
    data = s.recv(1024)
    json_data = json.loads(data)
    finalize_sig = json_data[1]
    balances = json_data[2]
    print('Received answer for Finalization', json.loads(data))
    print("Finalizing on contract")
    finalize_on_contract(contr, finalize_sig, finalization_filter)
    print("Exit")
    transactions, chain = exit_on_contract(pk_1, 9, balances[pk_1][1], start_exit_filter, exits_finalized_filter)
    s.sendall(to_bytes(text=create_exit_request(chain, transactions)))
    data = s.recv(1024)
    print(json.loads(data))
