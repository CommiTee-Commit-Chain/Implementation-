import os
import sys
scriptpath = "../"
sys.path.append(os.path.abspath(scriptpath))
from web3 import Web3, HTTPProvider
from web3.auto import w3
from eth_utils import to_hex
from eth_account.messages import encode_defunct
import contract
import utils

"""
Benchmarking by creating enclave values and using fixed keys
"""

pk_1 = "0x49079aF95b9F45BdAcEc269f49BdC5F6185C2B44"
sk_1 = "14b4e69dbcd3d069c835429e974ada13e4bd39c1debd1d7480bb0dbb07691a34"
pk_2 = "0xDaa4599e4F584816CE665f7D3A89F020d12541A6"
sk_2 = "0x2ce321bb3db167317a1f7c72fd7e4ab8b823734dd81d3d363acc1572767d8707"
pk_3 = "0x6d01EdDD750509B471166D1EC6c8370A3AFd141a"
pk_4 = "0xE4eDDaa6BB95e041186D8ECa685908D7F5A48531"
pk_5 = "0x8526f529F44102aC07A1860A2F4AE2869f30de8E"
pk_6 = "0x2DC63Be51606D04714BeD9227Fa36489f4abE501"
pk_7 = "0xfbbF696090f8b527C4848b4F42382fa8eB796ACe"
pk_8 = "0x0CfD1c72260470d07A349861ACFEedB51De13F14"
pk_9 = "0xd856bb8C25171FF3BE0037c58979c721eFa2b694"
pk_1_0 = "0xe2Bc4740b31Ae1960f9af9752b39a3b79493B335"

key_list = [pk_1, pk_2, pk_3, pk_4, pk_5, pk_6, pk_7, pk_8, pk_9, pk_1_0]
enclave_pk ="0x808aC95CE899AD7df76769f1DB8D719dAfa7Be6e"
enclave_sk = "0xeee831429bfc6748481000a6f2c6e12adc477dceeb53dbc73be1605ba19506ef"
gas_price = 20000000000


def create_finalization_values(sk, balance, index, party):
    sigma_E_msg = "updated|" + str(index)
    sigma_E = w3.eth.account.sign_message(encode_defunct(text=sigma_E_msg), private_key=sk)
    msg = str(index) + "|" + str(balance) + "|0x" + str.upper(party[2:])
    sigma_i = to_hex(w3.eth.account.sign_message(encode_defunct(text=msg),
                                                 private_key=sk).signature)
    return sigma_E_msg, to_hex(sigma_E.signature), msg, sigma_i


def set_enclave(_pk):
    contr.functions.set_enclave(_pk).transact()


def deposit(_pk, value):
    contr.functions.deposit(_pk).transact({"from": _pk, "value": web3.toWei(value, "ether")})


def start_exit(party, balance, v ,r ,s):
    contr.functions.exit(party, balance, v, r, s).transact()


def challenge(party):
    contr.functions.exit_challenge(party).transact()


def response_to_challenge(party, balance, v, r, s):
    contr.functions.respond_to_exit_challenge(party, balance, v, r, s).transact()


def finalize_exits():
    contr.functions.finalizeExits().transact()


def finalize(v=None, r=None , s=None, signer=None):
    if v is None:
        contr.functions.finalize_no_msg().transact()
    else:
        contr.functions.finalize(v, r, s, signer).transact()


web3 = Web3(HTTPProvider('http://localhost:8545'))
accounts = web3.eth.accounts
web3.eth.defaultAccount = accounts[0]
plasma_contract = contract.Contract(web3)
contr = plasma_contract.deploy_contract()
set_enclave(enclave_pk)
balance = 10
index = 0
num_of_deposits = 8
# Create deposits on the contract
for i, pk in enumerate(key_list):
    if i > num_of_deposits:
        break
    deposit(pk, 20)

# Finalize epochs
index += 1
finalize()
index += 1
finalize()
index += 1
finalize()
index += 1
finalize()

# Create exit challenges and responses on the contract
sigma_E_msg, sigma_E, msg, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_2)
v, r, s = utils.signature_from_hex_to_solidity(sigma_E)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
challenge(pk_2)
response_to_challenge(pk_2, balance, v_b, r_b, s_b)
sigma_E_msg, sigma_E, msg, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_5)
v, r, s = utils.signature_from_hex_to_solidity(sigma_E)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
challenge(pk_5)
response_to_challenge(pk_5, balance, v_b, r_b, s_b)
sigma_E_msg, sigma_E, msg, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_6)
v, r, s = utils.signature_from_hex_to_solidity(sigma_E)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
challenge(pk_6)
response_to_challenge(pk_6, balance, v_b, r_b, s_b)
# Finalize exits and epoch
finalize_exits()
index += 1
finalize()

# Start multiple regular exits on the contract
_, _, _, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_1)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
start_exit(pk_1, balance, v_b, r_b, s_b)
_, _, _, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_3)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
start_exit(pk_3, balance, v_b, r_b, s_b)
_, _, _, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_4)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
start_exit(pk_4, balance, v_b, r_b, s_b)
_, _, _, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_8)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
start_exit(pk_8, balance, v_b, r_b, s_b)
# Finalize exits and epoch
finalize_exits()
index += 1
finalize()

# Start single exit and finalize it
_, _, _, sigma_i = create_finalization_values(enclave_sk, balance, index, pk_7)
v_b, r_b, s_b = utils.signature_from_hex_to_solidity(sigma_i)
start_exit(pk_7, balance, v_b, r_b, s_b)
finalize_exits()