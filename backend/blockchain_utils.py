from web3 import Web3
import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

# We connect to Hardhat local node
w3 = Web3(Web3.HTTPProvider(os.getenv("WEB3_PROVIDER_URI", "http://127.0.0.1:8545")))

def get_contract():
    # Attempt to load the ABI from the hardhat artifacts
    compiled_contract_path = os.path.join(
        os.path.dirname(__file__), 
        "..", "blockchain", "artifacts", "contracts", "ThreatLog.sol", "ThreatLog.json"
    )
    
    if not os.path.exists(compiled_contract_path):
        raise Exception(f"Contract artifact not found at {compiled_contract_path}. Please compile the contract.")
        
    with open(compiled_contract_path, "r") as file:
        contract_json = json.load(file)
        contract_abi = contract_json["abi"]
        
    contract_address = os.getenv("CONTRACT_ADDRESS")
    if not contract_address:
        raise Exception("CONTRACT_ADDRESS must be set in the .env file")
        
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    return contract

def upload_evidence_to_ipfs(url_hash: str, features_dict: dict) -> str:
    """
    Mock pushing JSON evidence to an IPFS node (like Pinata).
    In a real-world scenario, you would use requests to POST to Pinata APIs.
    We return a fake decentralized content identifier (CID) for demonstration.
    """
    # Example of how Pinata API would be called:
    # headers = {'Authorization': f'Bearer {os.getenv("PINATA_JWT")}'}
    # payload = {'url_hash': url_hash, 'features': features_dict}
    # response = requests.post('https://api.pinata.cloud/pinning/pinJSONToIPFS', json=payload, headers=headers)
    # return response.json()['IpfsHash']
    
    # Returning a mock IPFS CID:
    import uuid
    mock_cid = "Qm" + str(uuid.uuid4()).replace("-", "") + "Ev1d3nc3"
    print(f"Evidence for {url_hash} pinned to IPFS at {mock_cid}")
    return mock_cid

def log_to_blockchain(url_hash: str, features_dict: dict = None):
    if not w3.is_connected():
        raise Exception("Failed to connect to blockchain node")
        
    contract = get_contract()
    
    # We use the first account for development
    account = w3.eth.accounts[0]
    
    # Check if already logged to avoid unnecessary transactions
    if contract.functions.isLogged(url_hash).call():
        print(f"{url_hash} is already logged on the blockchain")
        return
        
    # Generate IPFS hash for evidence
    ipfs_hash = "QmEmpty"
    if features_dict:
        ipfs_hash = upload_evidence_to_ipfs(url_hash, features_dict)
        
    # Call new solidity signature: addLog(string _urlHash, string _ipfsHash)
    tx_hash = contract.functions.addLog(url_hash, ipfs_hash).transact({'from': account})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    if receipt.status != 1:
        raise Exception("Transaction failed on blockchain")
        
    print(f"Successfully logged {url_hash} with IPFS evidence {ipfs_hash} to blockchain: TX {receipt.transactionHash.hex()}")
