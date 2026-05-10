const hre = require("hardhat");

async function main() {
  console.log("==========================================");
  console.log("  PHISHGUARD - BLOCKCHAIN EVENT WATCHER   ");
  console.log("==========================================");

  // We need the contract address from your backend/.env
  // For hardhat standard deployment, it's usually the first deployed address:
  // 0x5FbDB2315678afecb367f032d93F642f64180aa3
  const contractAddress = process.env.CONTRACT_ADDRESS || "0x5FbDB2315678afecb367f032d93F642f64180aa3";
  
  console.log(`Connecting to ThreatLog Contract at: ${contractAddress}`);
  console.log("Waiting for new Phishing logs to be sealed...\n");

  // Get the contract factory and attach it to the deployed address
  const ThreatLog = await hre.ethers.getContractFactory("ThreatLog");
  const contract = ThreatLog.attach(contractAddress);

  // Subscribe to the "LogAdded" event emitted by our Solidity contract
  contract.on("LogAdded", (urlHash, ipfsHash, timestamp, reporter) => {
    const date = new Date(timestamp * 1000).toLocaleString();
    
    console.log("🚨 [NEW THREAT DETECTED & SEALED ON-CHAIN] 🚨");
    console.log(`=> Time      : ${date}`);
    console.log(`=> URL Hash  : ${urlHash}`);
    console.log(`=> IPFS CID  : ${ipfsHash}`);
    console.log(`=> Reporter  : ${reporter}`);
    console.log("------------------------------------------");
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
