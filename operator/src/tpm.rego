package policy

import rego.v1

default hardware := 2

default configuration := 2

default executables := 33

## TPM validation
executables := 3 if {
	lower(input.tpm.pcrs[4]) in data.reference.tpm_pcr4
	lower(input.tpm.pcrs[14]) in data.reference.tpm_pcr14
}

# Azure SNP vTPM validation
executables := 3 if {
	lower(input.azsnpvtpm.tpm.pcr04) in data.reference.tpm_pcr4
	lower(input.azsnpvtpm.tpm.pcr14) in data.reference.tpm_pcr14
}
