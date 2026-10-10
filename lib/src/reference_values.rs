// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::{ApprovedImageStatusPcrs, ApprovedImageStatusPcrsEvents};
use compute_pcrs_lib::Pcr;
use compute_pcrs_lib::tpmevents::TPMEvent;

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

#[cfg(test)]
mod tests {
    use super::*;

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
