// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::Pcr;
use k8s_openapi::{
    api::core::v1::{ConfigMap, Secret},
    jiff::Timestamp,
};
use std::collections::BTreeMap;

use crate::trustee;
use trusted_cluster_operator_lib::reference_values::{ImagePcr, ImagePcrs, PCR_CONFIG_FILE};

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
