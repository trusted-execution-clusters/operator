// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::Pcr;
use k8s_openapi::jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PCR_CONFIG_MAP: &str = "image-pcrs";
pub const PCR_CONFIG_FILE: &str = "image-pcrs.json";
pub const IMAGE_VOLUME_MOUNTPOINT: &str = "/image";

#[derive(Deserialize, Serialize)]
pub struct ImagePcr {
    pub first_seen: Timestamp,
    pub pcrs: Vec<Pcr>,
    pub reference: String,
}

#[derive(Default, Deserialize, Serialize)]
pub struct ImagePcrs(pub BTreeMap<String, ImagePcr>);

#[macro_export]
macro_rules! update_image_pcrs {
    ($api:ident, $map:ident, $pcrs:ident) => {
        let image_pcrs_json = serde_json::to_string(&$pcrs)?;
        let map = (PCR_CONFIG_FILE.to_string(), image_pcrs_json.to_string());
        let data = std::collections::BTreeMap::from([map]);
        $map.data = Some(data);
        $api.replace(PCR_CONFIG_MAP, &Default::default(), &$map)
            .await?
    };
}
