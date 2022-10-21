# Mythril Realtime Vulnerabilities Scanning Agent

## Description

This agent scans possible vulnerabilities in newly created smart contracts using Mythril.

## Supported Chains

- All chains that Forta supports.

## Alerts

Describe each of the type of alerts fired by this agent

- FORTA-FAIL-SCAN
  - Fired when a contract fails to be scanned by the bot.
  - Severity is always set to "info".
  - Type is always set to "info".
  - Metadata:
    - contract: The address of the contract that failed to be scanned.
- FORTA-ISSUE-FOUND
  - Fired when an issue (possible vulnerability) is found in a contract.
  - Severity is set according to the severity of the issue.
  - Type is always set to "info".
  - Metadata:
    - contract: The address of the contract that failed to be scanned.
    - description: The description of the vunerability.

## Test Data

The agent behaviour can be verified with the following command:

- npm run tx 0x8c47f7730d6b93044436c8a553fb678e521d46113df5b26cc59041804a4198ad
