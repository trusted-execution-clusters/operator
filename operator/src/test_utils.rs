// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::Pcr;
use compute_pcrs_lib::tpmevents::{TPMEvent, TPMEventID};
use k8s_openapi::{api::core::v1::ConfigMap, jiff::Timestamp};
use kube::Client;
use operator::RvContextData;
use std::collections::BTreeMap;

use crate::trustee;
use trusted_cluster_operator_lib::reference_values::{ImagePcr, ImagePcrs, PCR_CONFIG_FILE};

pub const DUMMY_PCR_4_VALUE: &str =
    "3f263b96ccbc33bb53d808771f9ab1e02d4dec8854f9530f749cde853a723273";
pub const DUMMY_PCR_7_VALUE: &str =
    "e58ada1ba75f2e4722b539824598ad5e10c55f2e4aeab2033f3b0a8ee3f3eca6";

pub fn dummy_pcrs() -> ImagePcrs {
    ImagePcrs(BTreeMap::from([(
        "cos".to_string(),
        ImagePcr {
            first_seen: Timestamp::now(),
            pcrs: vec![
                Pcr {
                    id: 4,
                    value: hex::decode(DUMMY_PCR_4_VALUE).unwrap(),
                    events: vec![TPMEvent {
                        name: "EV_EFI_ACTION".into(),
                        pcr: 4,
                        hash: hex::decode(
                            "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr4EfiCall,
                    }],
                },
                Pcr {
                    id: 7,
                    value: hex::decode(DUMMY_PCR_7_VALUE).unwrap(),
                    events: vec![TPMEvent {
                        name: "EV_EFI_VARIABLE_DRIVER_CONFIG".into(),
                        pcr: 7,
                        hash: hex::decode(
                            "ccfc4bb32888a345bc8aeadaba552b627d99348c767681ab3141f5b01e40a40e",
                        )
                        .unwrap(),
                        id: TPMEventID::Pcr7SecureBoot,
                    }],
                },
            ],
            reference: "".to_string(),
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
