## Overview

This document describes the attestation key (AK) registration process for confidential clusters. The AK is provisioned and registered during first boot using clevis-pin-trustee's attestation support. The registered AK follows a Trust On First Use (TOFU) model, where the key is trusted upon initial registration and subsequently used by Trustee to verify attestation reports.

## Attestation Key Overview

The **Attestation Key (AK)** is a TPM-based cryptographic key used to sign attestation reports. It serves as the node's cryptographic identity in the attestation process:

- **Generation**: Created once during firstboot and stored persistently in the TPM
- **Purpose**: Signs attestation quotes that prove the node's platform state
- **Trust Model**: TOFU - trusted when first registered, used to verify all subsequent attestations
- **Persistence**: Stored at `/var/tpm/ak.pub` to prevent regeneration on subsequent boots

## TOFU (Trust On First Use) Model

The TOFU model simplifies the attestation workflow by establishing trust during the initial registration:

1. **First Registration**: During first boot, the node generates an AK and registers it with the attestation service
2. **Trust Establishment**: The operator accepts and stores the AK and verifies that the AK has been signed by the cloud provider EK of the TPM
3. **Subsequent Attestations**: All future attestation reports must be signed by the registered AK
4. **Verification**: Trustee validates that attestation quotes are signed by the known, registered AK

## Clevis pin configuration

The AK registration is configured through the Clevis pin's attestation section. This configuration is provided during the first boot merge process from the registration service.

### Configuration Schema

For example, an ignition config
```json
{
  "ignition": {
    "version": "3.6.0"
  },
  "storage": {
    "luks": [
      {
        "clevis": {
          "custom": {
            "config": "{\"attestation_key\":{...}, ...}",
            "needsNetwork": true,
            "pin": "trustee"
          },
          ...
        },
        ...
      }
    ],
    ...
  }
}
```

could contain the Clevis config

```
{
  "attestation_key": {
    "registration": {
      "url": "https://attestation-key-register.test-a359392a.svc.cluster.local:8001/register-ak",
      "cert": "-----BEGIN CERTIFICATE-----\nMIIDADCCAeigAwIBAgIUfF36UDMoK8YX+6RN1HxvusgPUgswDQYJKoZIhvcNAQEL\nBQAwGDEWMBQGA1UEAxMNc2VsZnNpZ25lZC1jYTAeFw0yNjEwMTYxNjE1MjBaFw0y\nNzAxMTQxNjE1MjBaMBgxFjAUBgNVBAMTDXNlbGZzaWduZWQtY2EwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwmKhSQJdrgKf+pv2WfDZ43pJMK6dKN317\nO5YflWDqt/xCkRIwdxPAcTGA0dbooA/epzDgbfsU6SHTWclPKg+Uag0KwgzdlPs7\n2uJw25zNnUdA6nLyDqxatbmsHR92Ny9vvmndMmvMQ7cbXpdzXi5asDKLTy3cYyc1\nc0SQ4BMppzvZjuM1BegZXcv7PHlDD+O84Bm+OlRcbdHiZNEUugMqHj/f+NUP43Oh\nGK7xRBx37DLZZvwnm7/5LUR09I4ktSDRKI9qcJawi1OsyLqSYsoKlnN4q+mW/DJ8\n1Hu1jbulTmDXi2PyrsSpYXPdrKrcLtlnHvfKMrxhLj1wBBleLUD7AgMBAAGjQjBA\nMA4GA1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSHMhju\nwEhNswW/c6bnSkKRDPug9DANBgkqhkiG9w0BAQsFAAOCAQEAQhgM0PW6Fwwq0BSz\nSKh2bFELqk5J0P37e4g2tivztACcUcV/3UAhKWGKHPjEx8pt7q1K8t3hbB4cBg4R\nLtagoXP+oRlpx6ESz525cxvLUDGAQK3P/q7mc1SwGzd7jtAPgZ+ULLyEvIj3Tki+\nGzZJh2Vasrx8d09K5wiiN5YUrXVArr7GLmQpHuDwqqE1y1Sre/Xo9nD2/LsveFVa\nkTihjRMfmlwR8T5H/za9bDagBSlby+Nhp9mjy5OrsCRcrlCY+31Copq7SA/uGQ14\nXgSIbBbgUgXUJp0UlyfSF64ao6fjSs+KukCIiz2vpPCpsG4Zseru7kx25v3foITF\ntWLvQw==\n-----END CERTIFICATE-----\n",
      "uuid": "fe66e706-e4eb-4f05-84ab-83c69cba5cef"
    }
  },
  ...
}
```


### Configuration Parameters

- **url**: HTTP(S) endpoint where the AK public key will be registered
- **cert**: (Optional) TLS certificate for secure communication with the registration service

## First boot AK Registration Flow

During first boot, clevis-pin-trustee handles the AK generation and registration before LUKS encryption setup.

### Process Flow (first boot)

1. **AK Existence Check**: Clevis pin checks if `/var/tpm/ak.pub` exists
1. **AK Generation**: If not present, Clevis pin generates a new AK in the TPM
   - AK is created with TPM-resident private key
   - Public key is extracted and saved to `/var/tpm/ak.pub`
1. **Registration Request**: Clevis pin PUTs the public AK to the registration URL with
   - the AK public key in PEM format
   - the UUID of the machine as given by the general registration server

### AK Generation Timing

The AK is generated **before** the LUKS encryption setup to ensure:
- The AK is available for any attestation required during disk encryption
- The AK registration is complete before the node becomes fully operational

## Operator Coordination

The Confidential Cluster Operator extends its existing responsibilities and offers a further endpoint for the AK registration and Trustee configuration.

1. **AK Registration Service**: Provides HTTP endpoint to receive and store AK public keys
1. **Match the AK with a Machine**: associate the AK with a machine which represent the node
1. **Approval of the AK**: when there is a matching machine the AK is approved. For the current design, the AK is provided by ignition during the first boot, but the registration mechanism is generic and can be done manually by the cluster admin or by another operator 
1. **Trustee Integration**: Updates Trustee with the registered AK for attestation verification

The ignition configuration with the AK registration endpoint need to be provided via the initial Ignition configuration.
