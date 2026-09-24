// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::trustee;
use compute_pcrs_lib::Pcr;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::ObjectMeta;
use kube::runtime::reflector::{self, Lookup, Store};
use kube::runtime::watcher;
use std::collections::BTreeMap;
use std::hash::Hash;
use trusted_cluster_operator_lib::TrustedExecutionCluster;
use trusted_cluster_operator_lib::reference_values::pcrs_to_status;
use trusted_cluster_operator_lib::{ApprovedImageStatusPcrs, Machine, MachineSpec};

/// Build a reflector [`Store`] pre-populated with `items`, for tests that
/// exercise code reading from an `OperatorContext` store instead of the API.
pub fn store_with<K>(items: Vec<K>) -> Store<K>
where
    K: Lookup + Clone + 'static,
    K::DynamicType: Eq + Hash + Clone + Default,
{
    let (store, mut writer) = reflector::store::<K>();
    writer.apply_watcher_event(&watcher::Event::Init);
    for item in items {
        writer.apply_watcher_event(&watcher::Event::InitApply(item));
    }
    writer.apply_watcher_event(&watcher::Event::InitDone);
    store
}

pub mod dummy_static_events {
    use compute_pcrs_lib::tpmevents::{TPMEvent, TPMEventID};

    // Ideally the name should be something like EV_EFI_BOOT_SERVICES_APPLICATION for shium, grub and even vmlinuz, but for readability and simplicity, we use the name of the file.
    // event id anyways uniquely identifies the event, so we are free to choose our own names.

    // events for pcr 4
    pub fn shim_aa() -> TPMEvent {
        TPMEvent {
            name: "shim".to_string(),
            pcr: 4,
            hash: vec![0xaa; 32],
            id: TPMEventID::Pcr4Shim,
        }
    }
    pub fn shim_11() -> TPMEvent {
        TPMEvent {
            name: "shim".to_string(),
            pcr: 4,
            hash: vec![0x11; 32],
            id: TPMEventID::Pcr4Shim,
        }
    }
    pub fn grub_22() -> TPMEvent {
        TPMEvent {
            name: "grub".to_string(),
            pcr: 4,
            hash: vec![0x22; 32],
            id: TPMEventID::Pcr4Grub,
        }
    }
    pub fn grub_bb() -> TPMEvent {
        TPMEvent {
            name: "grub".to_string(),
            pcr: 4,
            hash: vec![0xbb; 32],
            id: TPMEventID::Pcr4Grub,
        }
    }
    pub fn vmlinuz_cc() -> TPMEvent {
        TPMEvent {
            name: "vmlinuz".to_string(),
            pcr: 4,
            hash: vec![0xcc; 32],
            id: TPMEventID::Pcr4Vmlinuz,
        }
    }
    pub fn vmlinuz_33() -> TPMEvent {
        TPMEvent {
            name: "vmlinuz".to_string(),
            pcr: 4,
            hash: vec![0x33; 32],
            id: TPMEventID::Pcr4Vmlinuz,
        }
    }

    // events for pcr 7
    pub fn secure_boot_dd() -> TPMEvent {
        TPMEvent {
            name: "secure_boot".to_string(),
            pcr: 7,
            hash: vec![0xdd; 32],
            id: TPMEventID::Pcr7SecureBoot,
        }
    }
    pub fn shimcert_ee() -> TPMEvent {
        TPMEvent {
            name: "shimcert".to_string(),
            pcr: 7,
            hash: vec![0xee; 32],
            id: TPMEventID::Pcr7ShimCert,
        }
    }
    pub fn secure_boot_44() -> TPMEvent {
        TPMEvent {
            name: "secure_boot".to_string(),
            pcr: 7,
            hash: vec![0x44; 32],
            id: TPMEventID::Pcr7SecureBoot,
        }
    }

    // events for pcr 14
    pub fn mok_ff() -> TPMEvent {
        TPMEvent {
            name: "mokList".to_string(),
            pcr: 14,
            hash: vec![0xff; 32],
            id: TPMEventID::Pcr14MokList,
        }
    }
    pub fn mok_55() -> TPMEvent {
        TPMEvent {
            name: "mokList".to_string(),
            pcr: 14,
            hash: vec![0x55; 32],
            id: TPMEventID::Pcr14MokList,
        }
    }
}

pub fn dummy_pcrs() -> Vec<Pcr> {
    vec![
        // Build the PCR values from the events instead of harcoding constants. Events are the source of truth.
        Pcr::compile_from(&vec![
            dummy_static_events::shim_aa(),
            dummy_static_events::grub_bb(),
            dummy_static_events::vmlinuz_cc(),
        ]),
        Pcr::compile_from(&vec![
            dummy_static_events::secure_boot_dd(),
            dummy_static_events::shimcert_ee(),
        ]),
        Pcr::compile_from(&vec![dummy_static_events::mok_ff()]),
    ]
}

pub fn dummy_status_pcrs() -> Vec<ApprovedImageStatusPcrs> {
    pcrs_to_status(&dummy_pcrs())
}

pub fn dummy_pcr_value(pcr_id: u64) -> String {
    let pcrs = dummy_pcrs();
    pcrs.iter()
        .find(|p| p.id == pcr_id)
        .map(|p| hex::encode(&p.value))
        .unwrap()
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

pub fn dummy_cluster_with_mock_kbs(expected_requests: usize) -> TrustedExecutionCluster {
    use trusted_cluster_operator_test_utils::mock_client::dummy_cluster;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().take(expected_requests) {
            let mut stream = stream.unwrap();
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buf);
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        }
    });
    let mut cluster = dummy_cluster();
    cluster.spec.public_trustee_addr = Some(format!("127.0.0.1:{port}"));
    cluster
}

pub fn dummy_machine(id: &str) -> Machine {
    Machine {
        metadata: ObjectMeta {
            name: Some(id.to_string()),
            ..Default::default()
        },
        spec: MachineSpec {
            id: id.to_string(),
            provider_id: None,
        },
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
