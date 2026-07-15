// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

pub const TEC_NAME: &str = "trusted-execution-cluster";
pub const TRUSTEE_CONFIG_MAP: &str = "trustee-data";
pub const RV_JSON_KEY: &str = "reference-values.json";

pub const APPROVED_IMAGE_NAME: &str = "coreos-approved-primary";
pub const COMBINE_PCRS_UPDATE_TEST_IMAGE_NAME: &str = "coreos-test-update-combination";
// TODO: This image does not contain a custom ignition, neither a clevis pin.
//       It is just right to check that the operator fills the expected trustee
//       reference values in the integration test covering PCR combination.
//       However, it is not an image that supports attestation and so it will
//       always boot, even if reference values or policies were not configured
//       properly.
pub const COMBINE_PCRS_UPDATE_TEST_IMAGE_REF: &str = "quay.io/trusted-execution-clusters/fedora-coreos@sha256:372a5db90a8695fafc2869d438bacd7f0ef7fd84f63746a450bfcd4b8b64ae83";

pub const PRIMARY_PCR4_HASH: &str =
    "ff2b357be4a4bc66be796d4e7b2f1f27077dc89b96220aae60b443bcf4672525";
pub const SECONDARY_PCR4_HASH: &str =
    "37517a1f76c4d5cf615f4690921c732ad31359aac55f3aaf66d65a8ed38655a9";
pub const MIX_PRIMARY_BOOT_SECONDARY_KERNEL_PCR4_HASH: &str =
    "0c4e52c0bc5d2fedbf83b2fee82664dbe5347a79cfb2cbcb9a37f64211add6e8";
pub const MIX_SECONDARY_BOOT_PRIMARY_KERNEL_PCR4_HASH: &str =
    "cc5a5360e64b25718be370ca2056645a9ba9e9bae33df08308d6b8e05b8ebb87";
// PCR7 is not used for attestation yet. This constant is only consumed by
// unit tests.
pub const PCR7_HASH: &str = "b3a56a06c03a65277d0a787fcabc1e293eaa5d6dd79398f2dda741f7b874c65d";
pub const PCR14_HASH: &str = "17cdefd9548f4383b67a37a901673bf3c8ded6f619d36c8007562de1d93c81cc";

pub const SEPARATOR_HASH: &str = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119";
pub const EFICALL_HASH: &str = "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba";
pub const PRIMARY_SHIM_HASH: &str =
    "94896c17d49fc8c8df0cc2836611586edab1615ce7cb58cf13fc5798de56b367";
pub const PRIMARY_GRUB_HASH: &str =
    "bc6844fc7b59b4f0c7da70a307fc578465411d7a2c34b0f4dc2cc154c873b644";
pub const PRIMARY_KERNEL_HASH: &str =
    "72c613f1b4d60dcf51f82f3458cca246580d23150130ec6751ac6fa62c867364";
pub const SECONDARY_SHIM_HASH: &str = PRIMARY_SHIM_HASH;
pub const SECONDARY_GRUB_HASH: &str =
    "f45c2c974192366a5391e077c3cbf91e735e86eba2037fd86a1f1501818f73f4";
pub const SECONDARY_KERNEL_HASH: &str =
    "f31e645e5e9ed131eea5dca0a18893a21e5625b4a56314fa39587ddc33a7fa91";

#[macro_export]
macro_rules! pcr4_ev_efi_action_event {
    () => {{
        TPMEvent {
            pcr: 4,
            name: "EV_EFI_ACTION".to_string(),
            hash: hex::decode(EFICALL_HASH).unwrap(),
            id: TPMEventID::Pcr4EfiCall,
        }
    }};
}

#[macro_export]
macro_rules! pcr_separator_event {
    ($pcr:expr, $event_id:expr) => {{
        TPMEvent {
            pcr: $pcr,
            name: "EV_SEPARATOR".to_string(),
            hash: hex::decode(SEPARATOR_HASH).unwrap(),
            id: $event_id,
        }
    }};
}

#[macro_export]
macro_rules! expected_pcr7 {
    // PCR7 is not used for attestation yet. This constant is only consumed by
    // unit tests.
    () => {{
        Pcr {
            id: 7,
            value: hex::decode(PCR7_HASH).unwrap(),
            events: vec![
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                    hash: hex::decode(
                        "ccfc4bb32888a345bc8aeadaba552b627d99348c767681ab3141f5b01e40a40e",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7SecureBoot,
                },
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                    hash: hex::decode(
                        "adb6fc232943e39c374bf4782b6c697f43c39fca1f4b51dfceda21164e19a893",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7Pk,
                },
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                    hash: hex::decode(
                        "b5432fe20c624811cb0296391bfdf948ebd02f0705ab8229bea09774023f0ebf",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7Kek,
                },
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                    hash: hex::decode(
                        "4313e43de720194a0eabf4d6415d42b5a03a34fdc47bb1fc924cc4e665e6893d",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7Db,
                },
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_DRIVER_CONFIG".to_string(),
                    hash: hex::decode(
                        "001004ba58a184f09be6c1f4ec75a246cc2eefa9637b48ee428b6aa9bce48c55",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7Dbx,
                },
                pcr_separator_event!(7, TPMEventID::Pcr7Separator),
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_AUTHORITY".to_string(),
                    hash: hex::decode(
                        "4d4a8e2c74133bbdc01a16eaf2dbb5d575afeb36f5d8dfcf609ae043909e2ee9",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7ShimCert,
                },
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_AUTHORITY".to_string(),
                    hash: hex::decode(
                        "e8e9578f5951ef16b1c1aa18ef02944b8375ec45ed4b5d8cdb30428db4a31016",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7SbatLevel,
                },
                TPMEvent {
                    pcr: 7,
                    name: "EV_EFI_VARIABLE_AUTHORITY".to_string(),
                    hash: hex::decode(
                        "ad5901fd581e6640c742c488083b9ac2c48255bd28a16c106c6f9df52702ee3f",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr7GrubMokListCert,
                },
            ],
        }
    }};
}

#[macro_export]
macro_rules! expected_pcr14 {
    () => {{
        Pcr {
            id: 14,
            value: hex::decode(PCR14_HASH).unwrap(),
            events: vec![
                TPMEvent {
                    pcr: 14,
                    name: "EV_IPL".to_string(),
                    hash: hex::decode(
                        "e8e48e3ad10bc243341b4663c0057aef0ec7894ccc9ecb0598f0830fa57f7220",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr14MokList,
                },
                TPMEvent {
                    pcr: 14,
                    name: "EV_IPL".to_string(),
                    hash: hex::decode(
                        "8d8a3aae50d5d25838c95c034aadce7b548c9a952eb7925e366eda537c59c3b0",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr14MokListX,
                },
                TPMEvent {
                    pcr: 14,
                    name: "EV_IPL".to_string(),
                    hash: hex::decode(
                        "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
                    )
                    .unwrap(),
                    id: TPMEventID::Pcr14MokListTrusted,
                },
            ],
        }
    }};
}

#[macro_export]
macro_rules! pcr4_shim_event {
    ($hash:expr) => {{
        TPMEvent {
            pcr: 4,
            name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
            hash: hex::decode($hash).unwrap(),
            id: TPMEventID::Pcr4Shim,
        }
    }};
}

#[macro_export]
macro_rules! pcr4_grub_event {
    ($hash:expr) => {{
        TPMEvent {
            pcr: 4,
            name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
            hash: hex::decode($hash).unwrap(),
            id: TPMEventID::Pcr4Grub,
        }
    }};
}

#[macro_export]
macro_rules! pcr4_kernel_event {
    ($hash:expr) => {{
        TPMEvent {
            pcr: 4,
            name: "EV_EFI_BOOT_SERVICES_APPLICATION".to_string(),
            hash: hex::decode($hash).unwrap(),
            id: TPMEventID::Pcr4Vmlinuz,
        }
    }};
}

#[macro_export]
macro_rules! pcr4 {
    ($value:expr, $shim:expr, $grub:expr, $kernel:expr) => {{
        Pcr {
            id: 4,
            value: hex::decode($value).unwrap(),
            events: vec![
                pcr4_ev_efi_action_event!(),
                pcr_separator_event!(4, TPMEventID::Pcr4Separator),
                pcr4_shim_event!($shim),
                pcr4_grub_event!($grub),
                pcr4_kernel_event!($kernel),
            ],
        }
    }};
}

#[macro_export]
macro_rules! primary_pcr4 {
    () => {{
        pcr4!(
            PRIMARY_PCR4_HASH,
            PRIMARY_SHIM_HASH,
            PRIMARY_GRUB_HASH,
            PRIMARY_KERNEL_HASH
        )
    }};
}

// TODO: This should also contain expected pcr7, as soon as it can be
//       predicted and used for attestation
#[macro_export]
macro_rules! pcrs {
    ($pcr4:expr) => {{ [$pcr4, expected_pcr14!()] }};
}

#[macro_export]
macro_rules! primary_pcrs {
    () => {{ pcrs!(primary_pcr4!()) }};
}

#[macro_export]
macro_rules! secondary_pcrs {
    () => {{
        pcrs!(pcr4!(
            SECONDARY_PCR4_HASH,
            SECONDARY_SHIM_HASH,
            SECONDARY_GRUB_HASH,
            SECONDARY_KERNEL_HASH
        ))
    }};
}
