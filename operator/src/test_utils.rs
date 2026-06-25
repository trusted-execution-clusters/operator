// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::trustee;
use compute_pcrs_lib::Pcr;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use k8s_openapi::{
    api::core::v1::{ConfigMap, Secret},
    jiff::Timestamp,
};
use kube::api::ObjectMeta;
use std::collections::BTreeMap;
use trusted_cluster_operator_lib::reference_values::{ImagePcr, ImagePcrs, PCR_CONFIG_FILE};
use trusted_cluster_operator_lib::{Machine, MachineSpec};

pub fn dummy_pcrs() -> ImagePcrs {
    ImagePcrs(BTreeMap::from([(
        "cos".to_string(),
        ImagePcr {
            first_seen: Timestamp::now(),
            pcrs: vec![
                Pcr {
                    id: 0,
                    value: "pcr0_val".to_string(),
                    parts: vec![],
                },
                Pcr {
                    id: 1,
                    value: "pcr1_val".to_string(),
                    parts: vec![],
                },
            ],
            reference: "ref".to_string(),
        },
    )]))
}

pub fn dummy_trustee_map() -> ConfigMap {
    ConfigMap {
        data: Some(BTreeMap::from([(
            trustee::REFERENCE_VALUES_FILE.to_string(),
            "[]".to_string(),
        )])),
        ..Default::default()
    }
}

pub fn dummy_trustee_auth() -> Secret {
    let key_pair =
        trustee::generate_ed25519_key_pair().expect("Failed to generate ed25519 key pair");
    let data = BTreeMap::from([
        (
            trustee::TRUSTEE_AUTH_PRIV_KEY.to_string(),
            k8s_openapi::ByteString(key_pair.private_key_pem),
        ),
        (
            trustee::TRUSTEE_AUTH_PUB_KEY.to_string(),
            k8s_openapi::ByteString(key_pair.public_key_pem),
        ),
    ]);

    Secret {
        data: Some(data),
        ..Default::default()
    }
}

pub fn dummy_pcrs_map() -> ConfigMap {
    let data = BTreeMap::from([(
        PCR_CONFIG_FILE.to_string(),
        serde_json::to_string(&dummy_pcrs()).unwrap(),
    )]);
    ConfigMap {
        data: Some(data),
        ..Default::default()
    }
}

pub fn dummy_machine(id: &str) -> Machine {
    Machine {
        metadata: ObjectMeta {
            name: Some(id.to_string()),
            ..Default::default()
        },
        spec: MachineSpec { id: id.to_string() },
        status: None,
    }
}

pub fn dummy_ak_secret(name: &str) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            owner_references: Some(vec![OwnerReference {
                kind: "AttestationKey".to_string(),
                name: name.to_string(),
                uid: "ak-uid".to_string(),
                ..Default::default()
            }]),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(
            "public_key".to_string(),
            k8s_openapi::ByteString(b"test-ak-public-key".to_vec()),
        )])),
        ..Default::default()
    }
}
