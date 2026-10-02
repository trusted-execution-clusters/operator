// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::{ApprovedImageStatusPcrs, ApprovedImageStatusPcrsEvents};
use compute_pcrs_lib::Pcr;
use compute_pcrs_lib::tpmevents::TPMEvent;
use openssl::hash::{MessageDigest, hash};

#[cfg(feature = "openshift")]
pub const OSIMAGE_RESOURCE_PREFIX: &str = "osimage";

/// Name resource by uniquified RFC1035 name with a prefix
pub fn rfc1035(name: &str, prefix: &str) -> anyhow::Result<String> {
    if prefix.len() > 52 {
        return Err(anyhow::anyhow!("prefix too long"));
    }
    let replaced = name.replace(['.', ':', '/', '@', '_'], "-");
    let hash = hash(MessageDigest::sha1(), name.as_bytes())?;
    let hashed = hex::encode(hash)[..10].to_string();
    let formatted = format!("{prefix}-{hashed}-{replaced}");
    let trimmed: String = formatted.chars().take(63).collect();
    Ok(trimmed.trim_end_matches('-').to_string())
}

pub const IMAGE_VOLUME_MOUNTPOINT: &str = "/image";
// Convert Pcrs to ApprovedImageStatusPcrs
pub fn pcrs_to_status(pcrs: &[Pcr]) -> Vec<ApprovedImageStatusPcrs> {
    pcrs.iter()
        .map(|p| ApprovedImageStatusPcrs {
            id: p.id as i64,
            value: hex::encode(&p.value),
            events: Some(
                p.events
                    .iter()
                    .map(|e| ApprovedImageStatusPcrsEvents {
                        name: e.name.clone(),
                        pcr: e.pcr as i64,
                        hash: hex::encode(&e.hash),
                        id: format!("{:?}", e.id),
                    })
                    .collect(),
            ),
        })
        .collect()
}

// Convert ApprovedImageStatusPcrs to TPMEvents
pub fn status_to_tpm_events(pcrs: &[ApprovedImageStatusPcrs]) -> Vec<TPMEvent> {
    pcrs.iter()
        .flat_map(|p| {
            p.events.as_ref().map_or_else(Vec::new, |events| {
                events
                    .iter()
                    .filter_map(|e| {
                        // Any event that is not found in the list of known events is ignored.
                        let id = parse_tpm_event_id(&e.id)?;
                        let hash = hex::decode(&e.hash).ok()?;
                        // Ensure the PCR number is within the valid range.
                        let pcr = u8::try_from(e.pcr).ok()?;
                        Some(TPMEvent {
                            name: e.name.clone(),
                            pcr,
                            hash,
                            id,
                        })
                    })
                    .collect()
            })
        })
        .collect()
}

fn parse_tpm_event_id(s: &str) -> Option<compute_pcrs_lib::tpmevents::TPMEventID> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}
