// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use compute_pcrs_lib::*;
use env_logger::Env;
use k8s_openapi::{api::core::v1::ConfigMap, jiff::Timestamp};
use kube::{Api, Client};
use log::info;
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
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
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

    let image_pcr = ImagePcr {
        first_seen: Timestamp::now(),
        reference: args.image,
        pcrs,
    };
    // If we see this causing performance problems, consider NoSQL
    loop {
        let mut image_pcrs_map = config_maps.get(PCR_CONFIG_MAP).await?;
        let ctx = "Image PCRs map existed, but had no data";
        let image_pcrs_data = image_pcrs_map.data.context(ctx)?;
        let ctx = "Image PCRs data existed, but had no file";
        let image_pcrs_str = image_pcrs_data.get(PCR_CONFIG_FILE).context(ctx)?;
        let mut image_pcrs: ImagePcrs = serde_json::from_str(image_pcrs_str)?;
        let resource_name = args.resource_name.clone();
        image_pcrs.0.insert(resource_name, image_pcr.clone());
        let image_pcrs_json = serde_json::to_string(&image_pcrs)?;
        let map = (PCR_CONFIG_FILE.to_string(), image_pcrs_json);
        let data = std::collections::BTreeMap::from([map]);
        image_pcrs_map.data = Some(data);
        match config_maps
            .replace(PCR_CONFIG_MAP, &Default::default(), &image_pcrs_map)
            .await
        {
            Ok(_) => break,
            Err(kube::Error::Api(ae)) if ae.code == 409 => {
                info!("ConfigMap update conflict, retrying");
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }

    let approved_images: Api<ApprovedImage> = Api::default_namespaced(client);
    let image = approved_images.get(&args.resource_name).await?;
    let committed = committed_condition(INSTALLED_REASON, image.metadata.generation, &None);
    let conditions = Some(vec![committed]);
    let status = ApprovedImageStatus { conditions };
    update_status!(approved_images, &args.resource_name, status)?;
    Ok(())
}
