import { ApiPromise, WsProvider } from '@polkadot/api'
import { KeyringPair } from '@polkadot/keyring/types';
import { Codec } from '@polkadot/types/types';
import { options, OnChainRegistry, signCertificate, PinkContractPromise, ILooseResult } from '@phala/sdk'
import axios, { AxiosResponse } from 'axios';
import * as base64js from 'base64-js';
import * as fs from 'fs/promises';


// Define the structure of the report you expect to receive
interface IReport {
    report: string;
    signature: string;
    certificate: string;
}

interface IRequest {
    iasUrl?: string;
    iasKey: string;
    userReportData: Buffer;
    timeout?: number;
}

// Constants for default values
const DEFAULT_IAS_URL = 'https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report';
const DEFAULT_TIMEOUT = 10000; // milliseconds

async function createQuote(userReportData: Buffer): Promise<Buffer> {
    // Write data to a specific 'file'. The actual interaction would depend on your system's capabilities.
    await fs.writeFile('/dev/attestation/user_report_data', userReportData);
    // Read the quote from the specific 'file'. This assumes your environment supports these operations.
    const quote: Buffer = await fs.readFile('/dev/attestation/quote');
    return quote;
}

// Main function to get a report from Intel
async function createRemoteAttestationReport({
    userReportData,
    iasKey,
    iasUrl = DEFAULT_IAS_URL,
    timeout = DEFAULT_TIMEOUT
}: IRequest): Promise<IReport> {
    const quote: Buffer = await createQuote(userReportData);
    // Convert quote to Base64
    const encodedQuote = base64js.fromByteArray(quote);
    const encodedJson = JSON.stringify({ isvEnclaveQuote: encodedQuote });
    const client = axios.create({ timeout });

    // Send the request
    const response: AxiosResponse = await client.post(
        iasUrl,
        encodedJson,
        {
            headers: {
                'Connection': 'Close',
                'Content-Type': 'application/json',
                'Ocp-Apim-Subscription-Key': iasKey,
            },
            transformResponse: (r) => r,
        },
    );

    // Check for non-200 status codes
    if (response.status !== 200) {
        const messages: { [key: number]: string } = {
            401: 'Unauthorized: Failed to authenticate or authorize request.',
            404: 'Not Found: GID does not refer to a valid EPID group ID.',
            500: 'Internal error occurred.',
            503: 'Service is currently not able to process the request (due to a temporary overloading or maintenance). This is a temporary state – the same request can be repeated after some time.',
        };
        const msg = messages[response.status] || 'Unknown error occurred';
        throw new Error(`Bad HTTP status: ${response.status} - ${msg}`);
    }

    if (response.data.length === 0) {
        throw new Error('Empty HTTP response');
    }

    const report: string = response.data;
    const signature: string | undefined = response.headers['x-iasreport-signature'];
    const cert: string | undefined = response.headers['x-iasreport-signing-certificate'];

    if (!signature || !cert) {
        throw new Error('Required response headers for the attestation report are missing');
    }

    // Process the certificate and signature
    const decodedCert: string = decodeURIComponent(cert.replace(/%0A/g, ''));
    const splitCert: string[] = decodedCert.split('-----');
    const certificate: string = (splitCert.length > 2) ? splitCert[2] : '';

    return {
        report,
        signature,
        certificate,
    };
}

const VALIDATOR_ABI = '{"source":{"hash":"0xc00c5b038a7745e38cc9f5a78bfc4eb5fbb61b8b0bc28876ffb691272781c3a2","language":"ink! 4.2.0","compiler":"rustc 1.69.0","wasm":"","build_info":{"build_mode":"Release","cargo_contract_version":"4.0.0-alpha","rust_toolchain":"stable-x86_64-unknown-linux-gnu","wasm_opt_settings":{"keep_debug_symbols":false,"optimization_passes":"Z"}}},"contract":{"name":"pod_validator","version":"0.1.0","authors":["Kevin Wang <wy721@qq.com>"]},"image":null,"spec":{"constructors":[{"args":[],"default":false,"docs":[],"label":"default","payable":false,"returnType":{"displayName":["ink_primitives","ConstructorResult"],"type":0},"selector":"0xed4b9d1b"}],"docs":[],"environment":{"accountId":{"displayName":["AccountId"],"type":10},"balance":{"displayName":["Balance"],"type":12},"blockNumber":{"displayName":["BlockNumber"],"type":15},"chainExtension":{"displayName":["ChainExtension"],"type":16},"hash":{"displayName":["Hash"],"type":13},"maxEventTopics":4,"timestamp":{"displayName":["Timestamp"],"type":14}},"events":[],"lang_error":{"displayName":["ink","LangError"],"type":2},"messages":[{"args":[],"default":false,"docs":[" Returns the public key."],"label":"pubkey","mutates":false,"payable":false,"returnType":{"displayName":["ink","MessageResult"],"type":3},"selector":"0xa2f448a4"},{"args":[{"label":"report","type":{"displayName":["SignedReport"],"type":6}}],"default":false,"docs":[" Validates the given RA report and signs the inner user_report_data."],"label":"validate","mutates":false,"payable":false,"returnType":{"displayName":["ink","MessageResult"],"type":8},"selector":"0x5ae27423"}]},"storage":{"root":{"layout":{"struct":{"fields":[],"name":"Validator"}},"root_key":"0x00000000"}},"types":[{"id":0,"type":{"def":{"variant":{"variants":[{"fields":[{"type":1}],"index":0,"name":"Ok"},{"fields":[{"type":2}],"index":1,"name":"Err"}]}},"params":[{"name":"T","type":1},{"name":"E","type":2}],"path":["Result"]}},{"id":1,"type":{"def":{"tuple":[]}}},{"id":2,"type":{"def":{"variant":{"variants":[{"index":1,"name":"CouldNotReadInput"}]}},"path":["ink_primitives","LangError"]}},{"id":3,"type":{"def":{"variant":{"variants":[{"fields":[{"type":4}],"index":0,"name":"Ok"},{"fields":[{"type":2}],"index":1,"name":"Err"}]}},"params":[{"name":"T","type":4},{"name":"E","type":2}],"path":["Result"]}},{"id":4,"type":{"def":{"sequence":{"type":5}}}},{"id":5,"type":{"def":{"primitive":"u8"}}},{"id":6,"type":{"def":{"composite":{"fields":[{"name":"report","type":7,"typeName":"String"},{"name":"signature","type":7,"typeName":"String"},{"name":"certificate","type":7,"typeName":"String"}]}},"path":["pod_validator","pod_validator","SignedReport"]}},{"id":7,"type":{"def":{"primitive":"str"}}},{"id":8,"type":{"def":{"variant":{"variants":[{"fields":[{"type":9}],"index":0,"name":"Ok"},{"fields":[{"type":2}],"index":1,"name":"Err"}]}},"params":[{"name":"T","type":9},{"name":"E","type":2}],"path":["Result"]}},{"id":9,"type":{"def":{"variant":{"variants":[{"fields":[{"type":4}],"index":0,"name":"Ok"},{"fields":[{"type":7}],"index":1,"name":"Err"}]}},"params":[{"name":"T","type":4},{"name":"E","type":7}],"path":["Result"]}},{"id":10,"type":{"def":{"composite":{"fields":[{"type":11,"typeName":"[u8; 32]"}]}},"path":["ink_primitives","types","AccountId"]}},{"id":11,"type":{"def":{"array":{"len":32,"type":5}}}},{"id":12,"type":{"def":{"primitive":"u128"}}},{"id":13,"type":{"def":{"composite":{"fields":[{"type":11,"typeName":"[u8; 32]"}]}},"path":["ink_primitives","types","Hash"]}},{"id":14,"type":{"def":{"primitive":"u64"}}},{"id":15,"type":{"def":{"primitive":"u32"}}},{"id":16,"type":{"def":{"variant":{}},"path":["ink_env","types","NoChainExtension"]}}],"version":"4"}'

/// Request a signature from the validator contract.
async function sign(report: IReport, config: {
    rpc: string,
    pair: KeyringPair,
    contractId: string,
}): Promise<string> {
    const { rpc, pair, contractId } = config;
    const api = await ApiPromise.create(
        options({
            provider: new WsProvider(rpc),
            noInitWarn: true,
        })
    )
    const phatRegistry = await OnChainRegistry.create(api)
    const abi = JSON.parse(VALIDATOR_ABI)
    const contractKey = await phatRegistry.getContractKeyOrFail(contractId)
    const contract = new PinkContractPromise(api, phatRegistry, abi, contractId, contractKey)
    const cert = await signCertificate({ pair })
    const result = await contract.query.validate(pair.address, { cert }, report)
    const output = result.output as ILooseResult<ILooseResult<Codec>> | undefined
    if (output?.isOk && output.asOk.isOk) {
        return output.asOk.asOk.toHex();
    } else {
        throw new Error(`Failed to sign the report: ${result.result}`);
    }
}

export { createRemoteAttestationReport, sign };
