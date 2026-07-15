# Approved images for integration tests

There are two approved images that are used to run operator's
integration tests: The "primary", held by the `APPROVED_IMAGE`
environment variable in the [`Makefile`](/Makefile) and the "secondary",
defined in the `COMBINE_PCRS_UPDATE_TEST_IMAGE_REF` constant in
[`test_utils/src/constants.rs`](/tests/trusted_execution_cluster.rs).

Integration tests assume those are the images that the VMs joining the
test cluster are booting. Based on that assumption, a set of PCRs are
defined as constants in
[`test_utils/src/constants.rs`](/test_utils/src/constants.rs).
Constant variable names try to be self-explanatory.

In case any of the images need to be updated, the constant PCR values
that integration tests rely on might very likely need to be updated too.

## Updating approved images for integration tests
Approved images used in integration tests are usually Fedora CoreOS
images that are pinned in the trusted-execution-clusters quay.io. That
is, basically pulled from a CoreOS mirror and pushed into this
organization's. This is done so images are not garbage collected in the
original mirror and the team is not kept busy dealing with test approved
image updates so frequently.

Between the pull and the push, some image modifications shall be applied
to prepare the images to behave under the test cases. Mainly, to inject
the clevis-pin and a custom ignition to them. There is a helpful
[Containerfile][approved-image-containerfile] available in the investigations repository that does
exactly that.

[approved-image-containerfile]: https://github.com/trusted-execution-clusters/investigations/blob/3321d58394131b8c56430cf11a29dc0076c00f37/coreos/Containerfile

## Updating reference PCR values for integration tests

### When to update reference PCR value constants
In the event of an approved image pointer update, integration tests will
very likely break. Updating the reference PCR values should be enough to
fix them back.

In case the primary approved image was updated, `PRIMARY_*_HASH` consts
will need an update, as well as the `MIX_*_KERNEL_PCR4_HASH` consts.

For secondary approved image updates, `SECONDARY_*_HASH` and
`MIX_*_KERNEL_PCR4_HASH` constants will need to be updated.

In case both primary and secondary images are updated, all hashes will
need to be updated.

### How to compute reference PCR value constants
The easiest way to compute the new PCR values is certainly to use the
compute-pcrs library against the new image. However, that might not be
the most desirable way to do it, as it would implicitly bypass some of
the purpose of the integration tests.

The better way to do it is to boot the new image in a disposable VM and
check tpm event log.

In this document section we are going to focus just in PCR4.

First, a qcow2 image is needed. The bootable container image can be
"turned" into a qcow2 image. Another way, when it comes to CoreOS is to
find the image in the [CoreOS builds browser][coreos-build-browser] and
obtain its already built qcow2 relative.

To boot the VM, the investigations [`install_vm.sh`][installvm] script
might come in handy.

#### Boot stack event hashes
Once booted, log into the VM and run:
```bash
$ sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | \
    yq '.events[] |
      select(.PCRIndex == 4 and
      .EventType == "EV_EFI_BOOT_SERVICES_APPLICATION") |
      .Digests[] |
      select(.AlgorithmId == "sha256") |
      .Digest'
```
This should print 3 sha256 hash values. The ones relative to (in order
of appearance) shim, grub and the vmlinuz hashes.

If 3 values are not printed, it might be that secure boot was not
enabled in the VM, and the hash values should be just shim and grub's.
Make sure secure boot is enabled and try again.

Take those values and update the values of
`{PRIMARY|SECONDARY}_{SHIM,GRUB,KERNEL}_HASH` constants accordingly.

#### PCR4 hashes
Then again, run the following command in the VM:
```bash
$ sudo tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements | \
    yq '.pcrs.sha256.4' | \
    sed 's/^0x//'
```
This will print the resulting PCR4 hash of the new approved image.
Update the `PRIMARY_PCR4_HASH` or `SECONDARY_PCR4_HASH` value.

#### Combined PCR4 hashes
The tricky part comes with the combination (or mix) PCR4 hashes. These
model possible intermediate stages that the VM goes through during an
update. That includes the VM booting a new kernel through the old
bootloader, or booting the old kernel with a new bootloader in case of a
rollback being needed.

Set the shim and grub hashes of the primary image and the kernel hash of
the secondary image and run the following bash script:
```bash
hashes=(
    "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba"
    "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
    "${SHIM_HASH}"
    "${GRUB_HASH}"
    "${KERNEL_HASH}"
)
current_pcr="0000000000000000000000000000000000000000000000000000000000000000"
for event_hash in "${hashes[@]}"; do
    current_pcr=$(echo -n "${current_pcr}${event_hash}" | xxd -r -p | sha256sum | awk '{print $1}')
done
echo $current_pcr
```

The output is `MIX_PRIMARY_BOOT_SECONDARY_KERNEL_PCR4_HASH`. Then repeat
again with shim and grub hashes from the secondary image and the kernel
hash of the primary image to obtain
`MIX_SECONDARY_BOOT_PRIMARY_KERNEL_PCR4_HASH`.

[coreos-build-browser]: https://builds.coreos.fedoraproject.org/browser?stream=stable&arch=x86_64
[installvm]: https://github.com/trusted-execution-clusters/investigations/blob/f3bcaa95fff7c39092fae5cc63f9b31a2aacb221/scripts/install_vm.sh
