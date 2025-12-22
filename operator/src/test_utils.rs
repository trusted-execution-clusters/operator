// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::Pcr;
use k8s_openapi::{api::core::v1::ConfigMap, chrono::Utc};
use kube::Client;
use operator::RvContextData;
use std::collections::BTreeMap;

use crate::trustee;
use trusted_cluster_operator_lib::reference_values::{ImagePcr, ImagePcrs, PCR_CONFIG_FILE};

pub fn dummy_pcrs() -> ImagePcrs {
    ImagePcrs(BTreeMap::from([(
        "cos".to_string(),
        ImagePcr {
            first_seen: Utc::now(),
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

pub fn generate_rv_ctx(client: Client) -> RvContextData {
    RvContextData {
        client,
        owner_reference: Default::default(),
        pcrs_compute_image: String::new(),
    }
}
