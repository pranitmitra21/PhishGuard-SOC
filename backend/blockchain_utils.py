from web3 import Web3
import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Connect to external Web3 provider (Alchemy/Infura)
w3 = Web3(Web3.HTTPProvider(os.getenv("WEB3_PROVIDER_URI")))

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
    
    private_key = os.getenv("PRIVATE_KEY")
    if not private_key:
        raise Exception("PRIVATE_KEY must be set in the .env file to sign transactions")
        
    account = w3.eth.account.from_key(private_key)
    
    # Check if already logged to avoid unnecessary transactions
    if contract.functions.isLogged(url_hash).call():
        print(f"{url_hash} is already logged on the blockchain")
        return
        
    # Generate IPFS hash for evidence
    ipfs_hash = "QmEmpty"
    threat_details_json = "{}"
    if features_dict:
        ipfs_hash = upload_evidence_to_ipfs(url_hash, features_dict)
        # Create a highly compact JSON string to save gas on-chain
        compact_details = {
            "url": features_dict.get("url", "unknown"),
            "conf": round(features_dict.get("ml_confidence", 100.0), 1),
            "len": features_dict.get("url_length", 0),
            "sub": features_dict.get("num_subdomains", 0),
            "https": features_dict.get("is_https", True),
            "dom": features_dict.get("suspicious_dom_elements", 0)
        }
        threat_details_json = json.dumps(compact_details, separators=(',', ':'))
        
    # Build the transaction
    nonce = w3.eth.get_transaction_count(account.address)
    gas_price = w3.eth.gas_price

    # Low-balance warning
    balance_matic = float(w3.from_wei(w3.eth.get_balance(account.address), 'ether'))
    if balance_matic < 0.02:
        print(f"[Blockchain WARNING] Wallet balance low: {balance_matic:.4f} MATIC. Blockchain logging may stop soon.")

    # Use estimate_gas() instead of a hardcoded 2,000,000 which was 8x too large.
    # Add a 20% buffer for safety against estimation variance.
    try:
        estimated_gas = contract.functions.addLog(url_hash, ipfs_hash, threat_details_json).estimate_gas({'from': account.address})
        gas_limit = int(estimated_gas * 1.2)
    except Exception as e:
        print(f"[Blockchain] Gas estimation failed ({e}), falling back to 300,000")
        gas_limit = 300_000  # Reasonable fallback based on measured 252,338

    tx = contract.functions.addLog(url_hash, ipfs_hash, threat_details_json).build_transaction({
        'from': account.address,
        'nonce': nonce,
        'gas': gas_limit,
        'gasPrice': gas_price
    })
    
    # Sign the transaction
    signed_tx = w3.eth.account.sign_transaction(tx, private_key=private_key)
    
    # Send the raw transaction
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction) # Use raw_transaction in v6+
    
    # Wait for receipt
    # B8 FIX: Added timeout=120 seconds. Without a timeout, an unresponsive Sepolia node
    # or a dropped transaction would cause the background thread to hang indefinitely.
    print(f"Broadcasting TX to Ethereum Sepolia... Hash: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    
    if receipt.status != 1:
        raise Exception("Transaction failed on blockchain")
        
    print(f"Successfully logged {url_hash} with IPFS evidence {ipfs_hash} to blockchain: TX {receipt.transactionHash.hex()}")
