// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ThreatLog {
    struct PhishingLog {
        string urlHash; // SHA256 Hash of the URL
        string ipfsHash; // IPFS hash containing evidence (e.g. screenshot or DOM)
        uint256 timestamp;
        address reporter;
    }

    PhishingLog[] public logs;

    event LogAdded(string indexed urlHash, string ipfsHash, uint256 timestamp, address reporter);

    // Function to add a new phishing log with IPFS evidence
    function addLog(string calldata _urlHash, string calldata _ipfsHash) external {
        logs.push(PhishingLog({
            urlHash: _urlHash,
            ipfsHash: _ipfsHash,
            timestamp: block.timestamp,
            reporter: msg.sender
        }));

        emit LogAdded(_urlHash, _ipfsHash, block.timestamp, msg.sender);
    }

    // Function to get the total number of logs
    function getLogsCount() external view returns (uint256) {
        return logs.length;
    }

    // Function to check if a URL hash is already logged
    function isLogged(string calldata _urlHash) external view returns (bool) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (keccak256(abi.encodePacked(logs[i].urlHash)) == keccak256(abi.encodePacked(_urlHash))) {
                return true;
            }
        }
        return false;
    }
}
