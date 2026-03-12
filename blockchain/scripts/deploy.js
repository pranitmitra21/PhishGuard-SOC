const hre = require("hardhat");

async function main() {
    const ThreatLog = await hre.ethers.getContractFactory("ThreatLog");
    const threatLog = await ThreatLog.deploy();

    await threatLog.waitForDeployment();

    console.log("ThreatLog deployed to:", await threatLog.getAddress());
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
