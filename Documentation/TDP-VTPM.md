## TDP environment setup

Please follow [INSTALLATION_GUIDE] https://github.com/intel-staging/td-partitioning-svsm/blob/svsm-tdp-patches/INSTALLATION_GUIDE.md

## Features included
 - vTPM CRB MMIO interface
 - vTPM CA generation with TDX remote attestation
 - vTPM Endorsement Key Certificate and CA provision
 - SVSM/TDP L2 guest VTPM detection through TDVMCALL
 - SVSM TPM startup and measurement (SVSM version and TDVF).

## What has been tested
 - TPM event log replay in L2 Linux
 - Linux IMA
 - Endorsement Key certificate and CA certificate read and verify.
 - Quote verification

## Known Issues:
 - Page fault may be triggered when running `tpm2_createek` in L2 Linux
 - TSS reports `out of memory for object contexts` when running `keylime` in Linux.