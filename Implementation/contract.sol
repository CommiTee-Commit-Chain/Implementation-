pragma solidity ^0.5.3;

                    contract Plasma {
                        address owner;
                        address enclave_pk;
                        address payable[] parties;
                        uint [] tdep;
                        uint[] ptdep;
                        uint[] helperarr;
                        mapping (address => uint) indices;
                        mapping (address => bool) exits;
                        uint current_party_index = 1;
                        uint index = 0;
                        mapping (address => bool) challenges;
                        uint number_of_challenges;
                        uint state = 1;
                        address payable[] exiting_parties;
                        mapping(address => uint) exiting_amount;
                        
                        
                        struct Depositstr{
                            address payable owner;
                            uint amount;
                        }
                        Depositstr [] deposits;
                        Depositstr [] prev_deposits;
                        
                        // example enclave_pk 0x9E8f8b0c0E2123179ADC5e0E7CA09846821F767A
                        constructor() public {
                            owner = msg.sender;
                            tdep.push(0);
                            ptdep.push(0);
                            helperarr.push(0);
                        }
                        
                        function set_enclave(address enclave) public{
                            enclave_pk = enclave;
                        }
                        
                        function deposited(address _owner) public view returns (uint){
                            for (uint deposit_index = 0; deposit_index < deposits.length; deposit_index++){
                                Depositstr memory d = deposits[deposit_index];
                                if(d.owner == _owner){
                                    return d.amount;
                                }
                            }
                            return 0;
                        }
                        
                        function verifyString(string memory message, uint8 v, bytes32 r,
                                  bytes32 s, address signer) public view returns (bool) {    // The message header; we will fill in the length next
                            string memory header = "\x19Ethereum Signed Message:\n000000";    uint256 lengthOffset;
                            uint256 length;
                            assembly {
                              // The first word of a string is its length
                              length := mload(message)      // The beginning of the base-10 message length in the prefix
                              lengthOffset := add(header, 57)
                            }    // Maximum length we support
                            require(length <= 999999);    // The length of the message's length in base-10
                            uint256 lengthLength = 0;    // The divisor to get the next left-most message length digit
                            uint256 divisor = 100000;    // Move one digit of the message length to the right at a time
                            while (divisor != 0) {      // The place value at the divisor
                              uint256 digit = length / divisor;      if (digit == 0) {
                                // Skip leading zeros
                                if (lengthLength == 0) {
                                  divisor /= 10;
                                  continue;
                                }
                              }      // Found a non-zero digit or non-leading zero digit
                              lengthLength++;      // Remove this digit from the message length's current value
                              length -= digit * divisor;      // Shift our base-10 divisor over
                              divisor /= 10;
                              
                              // Convert the digit to its ASCII representation (man ascii)
                              digit += 0x30;      // Move to the next character and write the digit
                              lengthOffset++;
                              assembly {
                                mstore8(lengthOffset, digit)
                              }
                            }    // The null string requires exactly 1 zero (unskip 1 leading 0)
                            if (lengthLength == 0) {
                              lengthLength = 1 + 0x19 + 1;    } else {
                              lengthLength += 1 + 0x19;
                            }    // Truncate the tailing zeros from the header
                            assembly {
                              mstore(header, lengthLength)
                            }    // Perform the elliptic curve recover operation
                            bytes32 check = keccak256(abi.encodePacked(header, message));
                            return ecrecover(check, v, r, s) == signer;
                        }
                        
                        function addressToString(address _addr) public pure returns(string memory) {
                            bytes32 value = bytes32(uint256(_addr));
                            bytes memory alphabet = "0123456789ABCDEF";
                        
                            bytes memory str = new bytes(42);
                            str[0] = '0';
                            str[1] = 'x';
                            for (uint i = 0; i < 20; i++) {
                                str[2+i*2] = alphabet[uint(uint8(value[i + 12] >> 4))];
                                str[3+i*2] = alphabet[uint(uint8(value[i + 12] & 0x0f))];
                            }
                            return string(str);
                        }
                        
                        function uint2str(uint _i) internal pure returns (string memory _uintAsString) {
                            if (_i == 0) {
                                return "0";
                            }
                            uint j = _i;
                            uint len;
                            while (j != 0) {
                                len++;
                                j /= 10;
                            }
                            bytes memory bstr = new bytes(len);
                            uint k = len - 1;
                            while (_i != 0) {
                                bstr[k--] = byte(uint8(48 + _i % 10));
                                _i /= 10;
                            }
                            return string(bstr);
                        }
                    
                        event Deposit(address party);
                        function deposit(address payable p) public payable{
                            Depositstr memory d = Depositstr(p, msg.value);
                            deposits.push(d);
                            emit Deposit(p);
                        }
                        event ExitStart(address party, uint amount);
                        function exit(address payable party, uint balance, uint8 v_b, bytes32 r_b,
                                  bytes32 s_b) public{
//                            string memory exit_string = string(abi.encodePacked("exit|", uint2str(index), "|", addressToString(party)));
                            string memory balance_string = string(abi.encodePacked(uint2str(index), "|", uint2str(balance), "|", addressToString(party)));
                            if(number_of_challenges == 0 && verifyString(balance_string, v_b, r_b, s_b, enclave_pk) && !exits[party]){
                                //uint ind = indices[party];
                                exiting_parties.push(party);
                                uint deposits_amount = deposited(party);
                                exiting_amount[party] = balance + deposits_amount;
                                //party.transfer(balance + tdep[ind]);
                                emit ExitStart(party, exiting_amount[party]);
                            }
                        }

                        event ExitChallenge(address party);
                        function exit_challenge(address party) 
                            public {
                            if (!challenges[party] && !exits[party]){
                                challenges[party] = true;
                                number_of_challenges += 1;
                                emit ExitChallenge(party);
                            }
                        }
                        
                        function get_balance() public returns (uint){
                            return address(this).balance;
                        }
                        event ExitResponded(address party);
                        function respond_to_exit_challenge(address payable party,  uint balance, uint8 v_b, bytes32 r_b,
                                  bytes32 s_b) public{
                            string memory balance_string = string(abi.encodePacked(uint2str(index), "|", uint2str(balance), "|", addressToString(party)));
                            if(challenges[party] && verifyString(balance_string, v_b, r_b, s_b, enclave_pk)){
                                challenges[party] = false;
                                number_of_challenges -= 1;
                                //uint ind = indices[party];
                                exiting_parties.push(party);
                                uint deposits_amount = deposited(party);
                                exiting_amount[party] = balance + deposits_amount;
                                emit ExitResponded(party);
                            }
                        }
                        event ExitsFinalized();
                        event MaliciousOperator();
                        function finalizeExits() public payable returns(bool){
                            if (number_of_challenges == 0){
                                for (uint exit_index = 0; exit_index < exiting_parties.length; exit_index++){
                                    address payable user = exiting_parties[exit_index];
                                    if (!exits[user]){
                                        uint amount = exiting_amount[user];
                                        if (!address(user).send(amount)) {
                                                //handle failed send
                                                return false;
                                        }
                                        exits[user] = true;
                                        
                                    }
                                emit ExitsFinalized();
                                    
                                }
                                delete exiting_parties;
                                return true;
                            }
                            else{
                                index -= 1;
                                emit MaliciousOperator();
                            }
                        }
                        
                        event Finalization();
                        function finalize(uint8 v, bytes32 r, bytes32 s) public returns(bool){
                            string memory msg_string = string(abi.encodePacked("updated|", uint2str(index+1)));
                            if (msg.sender == owner && number_of_challenges == 0 && verifyString(msg_string, v, r, s, enclave_pk)){
                                if(deposits.length > 0){
                                    prev_deposits = deposits;
                                    delete deposits;
                                }
                                else{
                                    delete prev_deposits;
                                }
                                index += 1;
                                emit Finalization();
                                return true;
                            }
                        }
                        function finalize_no_msg() public returns(bool){
                            if (msg.sender == owner && number_of_challenges == 0){
                                if(deposits.length > 0){
                                    prev_deposits = deposits;
                                    delete deposits;
                                }
                                else{
                                    delete prev_deposits;
                                }
                                index += 1;
                                emit Finalization();
                                return true;
                            }
                        }

                    }
