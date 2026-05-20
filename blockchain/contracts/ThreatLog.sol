// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ThreatLog {
    struct PhishingLog {
        string url; // Original website URL
        string urlHash; // SHA256 Hash of the URL
        string ipfsHash; // IPFS hash containing full evidence report
        string threatDetails; // Compact JSON string with heuristic details
        uint256 timestamp;
        address reporter;
    }

    PhishingLog[] public logs;

    // O(1) lookup map: keccak256(urlHash bytes) => already logged?
    // Replaces the O(n) for-loop in the old isLogged(), saving gas at scale.
    mapping(bytes32 => bool) private _loggedHashes;

    event LogAdded(string url, string indexed urlHash, string ipfsHash, string threatDetails, uint256 timestamp, address reporter);

    // Function to add a new phishing log with detailed heuristics and IPFS evidence.
    // Reverts if the URL hash has already been logged (immutable audit trail).
    function addLog(string calldata _url, string calldata _urlHash, string calldata _ipfsHash, string calldata _threatDetails) external {
        bytes32 key = keccak256(abi.encodePacked(_urlHash));
        require(!_loggedHashes[key], "ThreatLog: URL hash already logged");

        _loggedHashes[key] = true;
        logs.push(PhishingLog({
            url: _url,
            urlHash: _urlHash,
            ipfsHash: _ipfsHash,
            threatDetails: _threatDetails,
            timestamp: block.timestamp,
            reporter: msg.sender
        }));

        emit LogAdded(_url, _urlHash, _ipfsHash, _threatDetails, block.timestamp, msg.sender);
    }

    // Function to get the total number of logs
    function getLogsCount() external view returns (uint256) {
        return logs.length;
    }

    // O(1) duplicate check — no loop, constant gas cost regardless of log size.
    function isLogged(string calldata _urlHash) external view returns (bool) {
        return _loggedHashes[keccak256(abi.encodePacked(_urlHash))];
    }
}
