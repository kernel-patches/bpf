#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -e
set -u
set -o pipefail

VERBOSE="${SELFTESTS_VERBOSE:=0}"
LOG_FILE="$(mktemp /tmp/verify_sig_setup.log.XXXXXX)"

x509_genkey_content="\
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
CN = eBPF Signature Verification Testing Key

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
"

gpg_genkey_content_common="\
     Name-Real: eBPF_UMD_Test
     Name-Comment: eBPF_UMD_Test
     Name-Email: ebpf_umd_test@localhost
     Expire-Date: 0
     Passphrase: abc
     %commit
"
gpg_genkey_content_rsa="\
     Key-Type: RSA
     Key-Length: 4096
     $gpg_genkey_content_common
"

gpg_genkey_content_ecdsa_p256="\
     Key-Type: ECDSA
     Key-Curve: NIST P-256
     $gpg_genkey_content_common
"

gpg_genkey_content_ecdsa_p384="\
     Key-Type: ECDSA
     Key-Curve: NIST P-384
     $gpg_genkey_content_common
"

usage()
{
	echo "Usage: $0 <setup|cleanup> <key type> <existing_tmp_dir>"
	exit 1
}

setup_pkcs7()
{
	local tmp_dir="$1"

	echo "${x509_genkey_content}" > ${tmp_dir}/x509.genkey

	openssl req -new -nodes -utf8 -sha256 -days 36500 \
			-batch -x509 -config ${tmp_dir}/x509.genkey \
			-outform PEM -out ${tmp_dir}/signing_key.pem \
			-keyout ${tmp_dir}/signing_key.pem 2>&1

	openssl x509 -in ${tmp_dir}/signing_key.pem -out \
		${tmp_dir}/signing_key.der -outform der

	key_id=$(cat ${tmp_dir}/signing_key.der | keyctl padd asymmetric ebpf_testing_key @s)

	keyring_id=$(keyctl newring ebpf_testing_keyring @s)
	keyctl link $key_id $keyring_id
}

setup_pgp()
{
	local tmp_dir="$1"
	local varname="gpg_genkey_content_$2"

	modprobe ecdsa_generic

	echo "${!varname}" > ${tmp_dir}/gpg.genkey
	gpg --batch --generate-key ${tmp_dir}/gpg.genkey

	key_id=$(gpg --export eBPF_UMD_Test | keyctl padd asymmetric ebpf_testing_key @s)
	keyring_id=$(keyctl newring ebpf_testing_keyring @s)
	keyctl link $key_id $keyring_id
}

cleanup_pkcs7() {
	local tmp_dir="$1"

	keyctl unlink $(keyctl search @s asymmetric ebpf_testing_key) @s
	keyctl unlink $(keyctl search @s keyring ebpf_testing_keyring) @s
	rm -rf ${tmp_dir}
}

cleanup_pgp() {
	local tmp_dir="$1"

	keyctl unlink $(keyctl search @s asymmetric ebpf_testing_key) @s
	keyctl unlink $(keyctl search @s keyring ebpf_testing_keyring) @s
	key_fingerprint=$(gpg --fingerprint --with-colons eBPF_UMD_Test | awk -F ":" '$1 == "fpr" {print $(NF-1)}')
	gpg --delete-secret-key --batch --yes $key_fingerprint
	gpg --delete-key --batch --yes $key_fingerprint
	rm -rf ${tmp_dir}
}

catch()
{
	local exit_code="$1"
	local log_file="$2"

	if [[ "${exit_code}" -ne 0 ]]; then
		cat "${log_file}" >&3
	fi

	rm -f "${log_file}"
	exit ${exit_code}
}

main()
{
	[[ $# -ne 4 ]] && usage

	local action="$1"
	local key_type="$2"
	local key_algo="$3"
	local tmp_dir="$4"

	[[ ! -d "${tmp_dir}" ]] && echo "Directory ${tmp_dir} doesn't exist" && exit 1

	if [[ "${action}" == "setup" ]]; then
		if [[ "${key_type}" == "pkcs7" ]]; then
			setup_pkcs7 "${tmp_dir}"
		elif [[ "${key_type}" == "pgp" ]]; then
			setup_pgp "${tmp_dir}" "${key_algo}"
		else
			echo "Unknown key type: ${key_type}"
			exit 1
		fi
	elif [[ "${action}" == "cleanup" ]]; then
		if [[ "${key_type}" == "pkcs7" ]]; then
			cleanup_pkcs7 "${tmp_dir}"
		elif [[ "${key_type}" == "pgp" ]]; then
			cleanup_pgp "${tmp_dir}"
		else
			echo "Unknown key type: ${key_type}"
			exit 1
		fi
	else
		echo "Unknown action: ${action}"
		exit 1
	fi
}

trap 'catch "$?" "${LOG_FILE}"' EXIT

if [[ "${VERBOSE}" -eq 0 ]]; then
	# Save the stderr to 3 so that we can output back to
	# it incase of an error.
	exec 3>&2 1>"${LOG_FILE}" 2>&1
fi

main "$@"
rm -f "${LOG_FILE}"
