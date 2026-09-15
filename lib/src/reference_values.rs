// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::{ApprovedImageStatusPcrs, ApprovedImageStatusPcrsEvents};
use compute_pcrs_lib::Pcr;
use compute_pcrs_lib::tpmevents::TPMEvent;
use openssl::hash::{MessageDigest, hash};

/// Name resource by uniquified RFC1035 name with a prefix
pub fn rfc1035(name: &str, prefix: &str) -> anyhow::Result<String> {
    if prefix.len() > 52 {
        return Err(anyhow::anyhow!("prefix too long"));
    }
    let lower = name.to_ascii_lowercase();
    let replaced = lower.replace(['.', ':', '/', '@', '_'], "-");
    let hash = hash(MessageDigest::sha1(), name.as_bytes())?;
    let hashed = hex::encode(hash)[..10].to_string();
    let formatted = format!("{prefix}-{hashed}-{replaced}");
    let trimmed: String = formatted.chars().take(63).collect();
    Ok(trimmed.trim_end_matches('-').to_string())
}

pub const IMAGE_VOLUME_MOUNTPOINT: &str = "/image";
pub const PCR_COMMAND_NAME: &str = "compute-pcrs";

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

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_cluster_operator_test_utils::constants::DUMMY_IMAGE_REF;

    #[test]
    fn test_rfc1035_trailing_dash() {
        let name = rfc1035("quay.io/some_ref:Some-tag-", PCR_COMMAND_NAME).unwrap();
        assert_eq!(name, "compute-pcrs-5a33fc23b3-quay-io-some-ref-some-tag");
    }

    #[test]
    fn test_rfc1035_sha() {
        let name = rfc1035(DUMMY_IMAGE_REF, PCR_COMMAND_NAME).unwrap();
        assert_eq!(
            name,
            "compute-pcrs-6c57e93939-quay-io-some-ref-sha256-e71dad00aa0e3d7"
        );
    }

    /// Detects drift between TPMEventID variants and parse_tpm_event_id.
    /// If a new event variant is added to compute-pcrs-lib without updating the match in this file, this test will fail with the name of the missing variant.
    #[test]
    fn parse_tpm_event_id_covers_all_variants() {
        use compute_pcrs_lib::tpmevents::TPMEventID;
        let mut i = 0;
        while let Some(variant) = TPMEventID::from_repr(i) {
            let s = format!("{:?}", variant);
            assert!(
                parse_tpm_event_id(&s).is_some(),
                "parse_tpm_event_id does not handle TPMEventID::{s} (repr {i}); \
                update the match in lib/src/reference_values.rs"
            );
            i += 1;
        }
    }
}
