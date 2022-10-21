import json

import rlp
from forta_agent import Finding, FindingType, FindingSeverity, get_json_rpc_url
from web3 import Web3
from subprocess import check_output, CalledProcessError


w3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))


def output_of(command, stderr=None):
    """
    :param command:
    :return:
    """
    try:
        return check_output(command, shell=True, stderr=stderr).decode("UTF-8")
    except CalledProcessError as exc:
        return exc.output.decode("UTF-8")


def calc_contract_address(address, nonce) -> str:
    """
    this function calculates the contract address from sender/nonce
    :return: contract address: str
    """

    address_bytes = bytes.fromhex(address[2:].lower())
    return Web3.toChecksumAddress(Web3.keccak(rlp.encode([address_bytes, nonce]))[-20:])


def myth_it(bytecode):
    command = f"""myth a -c {bytecode} -o json"""
    output = json.loads(output_of(command))
    return output


def handle_transaction(transaction_event):
    global w3
    findings = []

    for trace in transaction_event.traces:
        if trace.type == 'create':
            if transaction_event.from_ == trace.action.from_:
                # for contracts creating other contracts, the nonce would be 1
                nonce = transaction_event.transaction.nonce if transaction_event.from_ == trace.action.from_ else 1
                created_contract_address = calc_contract_address(trace.action.from_, nonce)
                bytecode = w3.eth.get_code(created_contract_address).hex()

                analysis = myth_it(bytecode)
                print(analysis)
                if not analysis['success']:
                    findings.append(Finding({
                        'name': 'Failed Scan',
                        'description': f'Fail to scan contract: {analysis["error"]}',
                        'alert_id': 'FORTA-FAIL-SCAN',
                        'severity': FindingSeverity.Info,
                        'type': FindingType.Info,
                        'metadata': {
                            'contract': created_contract_address,
                        }
                    }))

                if len(analysis['issues']) > 0:
                    for issue in analysis['issues']:
                        function = issue["function"]
                        title = issue["title"]
                        description = issue["description"]
                        if issue["severity"] == "High":
                            severity = FindingSeverity.High
                        elif issue["severity"] == "Medium":
                            severity = FindingSeverity.Medium
                        elif issue["severity"] == "Low":
                            severity = FindingSeverity.Low
                        else:
                            severity = FindingSeverity.Info
                        findings.append(Finding({
                            'name': 'Found Possible Vulnerabilities',
                            'description': f'Found possible issue: {title} in function {function}',
                            'alert_id': 'FORTA-ISSUE-FOUND',
                            'severity': severity,
                            'type': FindingType.Info,
                            'metadata': {
                                'contract': created_contract_address,
                                'description': description,
                            }
                        }))

    return findings
