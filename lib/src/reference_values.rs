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
                        Some(TPMEvent {
                            name: e.name.clone(),
                            pcr: e.pcr as u8,
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
    use compute_pcrs_lib::tpmevents::TPMEventID;
    match s {
        "PcrRootNodeEvent" => Some(TPMEventID::PcrRootNodeEvent),
        "Pcr4EfiCall" => Some(TPMEventID::Pcr4EfiCall),
        "Pcr4Separator" => Some(TPMEventID::Pcr4Separator),
        "Pcr4Shim" => Some(TPMEventID::Pcr4Shim),
        "Pcr4Grub" => Some(TPMEventID::Pcr4Grub),
        "Pcr4Vmlinuz" => Some(TPMEventID::Pcr4Vmlinuz),
        "Pcr7SecureBoot" => Some(TPMEventID::Pcr7SecureBoot),
        "Pcr7Pk" => Some(TPMEventID::Pcr7Pk),
        "Pcr7Kek" => Some(TPMEventID::Pcr7Kek),
        "Pcr7Db" => Some(TPMEventID::Pcr7Db),
        "Pcr7Dbx" => Some(TPMEventID::Pcr7Dbx),
        "Pcr7Separator" => Some(TPMEventID::Pcr7Separator),
        "Pcr7ShimCert" => Some(TPMEventID::Pcr7ShimCert),
        "Pcr7SbatLevel" => Some(TPMEventID::Pcr7SbatLevel),
        "Pcr7GrubDbCert" => Some(TPMEventID::Pcr7GrubDbCert),
        "Pcr7GrubVendorDbCert" => Some(TPMEventID::Pcr7GrubVendorDbCert),
        "Pcr7GrubMokListCert" => Some(TPMEventID::Pcr7GrubMokListCert),
        "Pcr11Linux" => Some(TPMEventID::Pcr11Linux),
        "Pcr11LinuxContent" => Some(TPMEventID::Pcr11LinuxContent),
        "Pcr11Osrel" => Some(TPMEventID::Pcr11Osrel),
        "Pcr11OsrelContent" => Some(TPMEventID::Pcr11OsrelContent),
        "Pcr11Cmdline" => Some(TPMEventID::Pcr11Cmdline),
        "Pcr11CmdlineContent" => Some(TPMEventID::Pcr11CmdlineContent),
        "Pcr11Initrd" => Some(TPMEventID::Pcr11Initrd),
        "Pcr11InitrdContent" => Some(TPMEventID::Pcr11InitrdContent),
        "Pcr11Uname" => Some(TPMEventID::Pcr11Uname),
        "Pcr11UnameContent" => Some(TPMEventID::Pcr11UnameContent),
        "Pcr11Sbat" => Some(TPMEventID::Pcr11Sbat),
        "Pcr11SbatContent" => Some(TPMEventID::Pcr11SbatContent),
        "Pcr14MokList" => Some(TPMEventID::Pcr14MokList),
        "Pcr14MokListX" => Some(TPMEventID::Pcr14MokListX),
        "Pcr14MokListTrusted" => Some(TPMEventID::Pcr14MokListTrusted),
        "PcrLastNodeEvent" => Some(TPMEventID::PcrLastNodeEvent),
        _ => None,
    }
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
