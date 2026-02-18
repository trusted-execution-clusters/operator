// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use compute_pcrs_lib::*;
use k8s_openapi::{api::core::v1::ConfigMap, jiff::Timestamp};
use kube::{Api, Client};
use std::{fs::File, io::Read};

use trusted_cluster_operator_lib::{conditions::INSTALLED_REASON, reference_values::*, *};

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// ApprovedImage resource name
    #[arg(short, long)]
    resource_name: String,
    /// Image reference
    #[arg(short, long)]
    image: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let kernels = format!("{IMAGE_VOLUME_MOUNTPOINT}/usr/lib/modules");
    let esp = format!("{IMAGE_VOLUME_MOUNTPOINT}/usr/lib/bootupd/updates");

    let mut os_release_file = File::open(format!("{IMAGE_VOLUME_MOUNTPOINT}/etc/os-release"))?;
    let mut os_release_content = String::new();
    os_release_file.read_to_string(&mut os_release_content)?;
    let get_val = |key: &str| {
        os_release_content
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim_matches('"'))
            .ok_or(anyhow!("/etc/os-release missed key: {key}"))
    };
    let os_id = get_val("ID")?;
    let os_version_id = get_val("VERSION_ID")?;

    let efivars = format!("/reference-values/efivars/qemu-ovmf/{os_id}-{os_version_id}");
    let mokvars = format!("/reference-values/mok-variables/{os_id}-{os_version_id}");

    let pcrs = vec![
        compute_pcr4(&kernels, &esp, false, true),
        compute_pcr7(Some(&efivars), &esp, true),
        compute_pcr14(&mokvars),
    ];

    let client = Client::try_default().await?;
    let config_maps: Api<ConfigMap> = Api::default_namespaced(client.clone());

    let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
    let image_pcrs_data = image_pcrs_map
        .data
        .context("Image PCRs map existed, but had no data")?;
    let image_pcrs_str = image_pcrs_data
        .get(PCR_CONFIG_FILE)
        .context("Image PCRs data existed, but had no file")?;
    let mut image_pcrs: ImagePcrs = serde_json::from_str(image_pcrs_str)?;

    let image_pcr = ImagePcr {
        first_seen: Timestamp::now(),
        reference: args.image,
        pcrs,
    };
    image_pcrs.0.insert(args.resource_name.clone(), image_pcr);
    update_image_pcrs!(config_maps, image_pcrs_map, image_pcrs);

    let approved_images: Api<ApprovedImage> = Api::default_namespaced(client);
    let image = approved_images.get(&args.resource_name).await?;
    let committed = committed_condition(INSTALLED_REASON, image.metadata.generation);
    let conditions = Some(vec![committed]);
    let status = ApprovedImageStatus { conditions };
    update_status!(approved_images, &args.resource_name, status)?;
    Ok(())
}
