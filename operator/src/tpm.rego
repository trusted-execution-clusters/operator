package policy

import rego.v1

default executables := 33

## TPM validation
executables := 3 if {
  input.tpm.pcr04 in query_reference_value("tpm_pcr4")
  input.tpm.pcr14 in query_reference_value("tpm_pcr14")

}
# Azure SNP vTPM validation
executables := 3 if {
  input["az-snp-vtpm"].tpm.pcr04 in query_reference_value("tpm_pcr4")
  input["az-snp-vtpm"].tpm.pcr14 in query_reference_value("tpm_pcr14")
}

default configuration := 0
default hardware := 0
default file_system := 0
default instance_identity := 0
default runtime_opaque := 0
default storage_opaque := 0
default sourced_data := 0
trust_claims := {
  "executables": executables,
  "hardware": hardware,
  "configuration": configuration,
  "file-system": file_system,
  "instance-identity": instance_identity,
  "runtime-opaque": runtime_opaque,
  "storage-opaque": storage_opaque,
  "sourced-data": sourced_data,
}
