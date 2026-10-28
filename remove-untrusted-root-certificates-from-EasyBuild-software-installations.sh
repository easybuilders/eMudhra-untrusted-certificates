#!/bin/bash
#
# Script to remove untrusted root certificates from software installations created with EasyBuild
#
# see https://emudhra.we-have-a-problem.com
#
# SPDX-License-Identifier: GPL-2.0-only
#
# author: EasyBuild maintainers

set -u

MODE="UNKNOWN"
TYPE="PATTERN"
VERBOSE="no"

LOGFILE_NAME="remove-untrusted-root-certificates-from-EasyBuild-software-installations.log"
LOGFILE=$(mktemp -p . ${LOGFILE_NAME}.XXXXXXXXXX)

function print_error() {
    /usr/bin/echo -e '\033[0;31m'"${1}"'\033[0m'
}

function print_ok() {
    /usr/bin/echo -e '\033[0;32m'"${1}"'\033[0m'
}

function print_warning() {
    /usr/bin/echo -e '\033[0;33m'"${1}"'\033[0m'
}

function echo_and_append_to_log {
    msg="$1"

    echo="/usr/bin/echo -e"
    to_stderr="no"
    info_msg="no"

    /usr/bin/echo -e "${msg}" | /usr/bin/grep "\[ERROR\]" > /dev/null
    if [[ $? -eq 0 ]]; then
        echo="print_error"
        to_stderr="yes"
    fi
    /usr/bin/echo -e "${msg}" | /usr/bin/grep "\[OK\]" > /dev/null
    if [[ $? -eq 0 ]]; then
        echo="print_ok"
        info_msg="yes"
    fi
    /usr/bin/echo -e "${msg}" | grep "\[WARNING\]" > /dev/null
    if [[ $? -eq 0 ]]; then
        echo="print_warning"
        to_stderr="yes"
    fi
    /usr/bin/echo -e "${msg}" | grep "\[INFO\]" > /dev/null
    if [[ $? -eq 0 ]]; then
        info_msg="yes"
    fi

    if [[ ${to_stderr} == "yes" ]]; then
        ${echo} "${msg}" >&2
    elif [[ ${info_msg} == "yes" ]] || [[ ${VERBOSE} == "yes" ]]; then
        ${echo} "${msg}"
    fi

    # no colors for logging
    /usr/bin/echo -e "${msg}" >> "${LOGFILE}"
}

function fail {
    msg="\n\n[FAIL] ${1}\n\n"
    print_error "${msg}" >&2
    /usr/bin/echo -e "${msg}" >> "${LOGFILE}"
    echo -e "\n(log: ${LOGFILE})\n"
    exit 1
}

echo ">> logging to ${LOGFILE}"
echo_and_append_to_log ">> [INFO] start time: $(date)"
# abort early if we can't log
if [ $? -ne 0 ]; then
    fail "Logging failed, giving up!"
fi

BEGIN_CERT='-----BEGIN CERTIFICATE-----'
END_CERT='-----END CERTIFICATE-----'

# patterns for untrusted certificates should be the start of the certificate,
# right after the '-----BEGIN CERTIFICATE-----' line

# emSign ECC Root CA - G3
# see https://github.com/certifi/python-certifi/pull/437
# some of these removed certificates were later restored in https://github.com/certifi/python-certifi/pull/440,
# see also https://github.com/certifi/python-certifi/issues/439
UNTRUSTED_EMSIGN_ROOT_CERT_PATTERN='MIICTjCCAdOgAwIBAgIKPPYHqWhwDt'

# AAA Certificate Services (Comodo)
# see https://github.com/certifi/python-certifi/pull/347
UNTRUSTED_COMODO_ROOT_CERT_PATTERN='MIIEMjCCAxqgAwIBAgIBATANBgkqhk'

UNTRUSTED_ROOT_CERT_PATTERNS=(
    ${UNTRUSTED_EMSIGN_ROOT_CERT_PATTERN}
    ${UNTRUSTED_COMODO_ROOT_CERT_PATTERN}
)

BACKUP_TAG="with-untrusted-root-cert"

function remove_untrusted_root_cert() {
    local cert_pattern=$1
    local path=$2

    if [[ ! -f ${path} ]]; then
        fail "Path does not exist: ${path}"
    fi
    if [[ ${MODE} == "REMOVE" ]]; then

        # make sure type of file is known
        if [[ $(basename "${path}") == *.pem || $(basename "${path}") == *.crt ]]; then

            # check again for pattern, better safe than sorry
            /usr/bin/grep "^${cert_pattern}" "${path}" > /dev/null
            if [[ $? -eq 0 ]]; then

                echo_and_append_to_log ">> removing untrusted root certificate from ${path} ..."

                parent_dir=$(dirname ${path})

                # we want to create a backup of the file we're patching, so make sure dir is writable to us
                restore_dir_read_only="no"
                restore_file_read_only="no"
                if [[ ! -w ${parent_dir} ]]; then
                    echo_and_append_to_log ">> enabling write permissions on ${parent_dir} ..."
                    chmod u+w ${parent_dir}
                    if [[ $? -ne 0 ]]; then
                        fail "Enabling write permissions on ${parent_dir} failed, giving up..."
                    fi
                    restore_dir_read_only="yes"
                fi

                # create backup
                backup=${path}.bk.${BACKUP_TAG}
                if [[ -f ${backup} ]]; then
                    old_backup=${backup}.$(date +%s)
                    mv ${backup} ${old_backup}
                    echo_and_append_to_log ">> old backup moved to ${old_backup}"
                fi
                cp -a ${path} ${backup}
                if [[ $? -eq 0 ]]; then
                    echo_and_append_to_log ">> backup copy of $(basename ${path}): ${backup}"
                else
                    fail "Making backup copy of ${path} failed, giving up..."
                fi

                # file must be writeable to change it, enable write permissions if needed
                if [[ ! -w ${path} ]]; then
                    # try to make path writable
                    echo_and_append_to_log ">> enabling write permissions on ${path} ..."
                    chmod u+w ${path}
                    if [[ $? -ne 0 ]]; then
                        fail "Enabling write permissions on ${parent_dir} failed, giving up..."
                    fi
                    restore_file_read_only="yes"
                fi

                # actually remove root cert
                echo_and_append_to_log ">> Removing untrusted root cert from ${path}"

                # use Perl to edit file in place to remove the certificate;
                #
                # remove block of text that starts with $BEGIN_CERT, ends with $END_CERT,
                # and includes the certificate pattern on line right after $BEGIN_CERT;
                #
                # take into account that line endings may be carriage return + newline (\r\n)
                # instead of just newline (\n)
                #
                # use .*? to make search non-greedy, so first $END_CERT completes the match
                #
                # non-empty lines preceding $BEGIN_CERT that don't start with --- are also removed,
                # for which a negative lookahead assertion is used, see (?!...);
                #
                # options:
                #   -0777: sets the input record separator ($/) + read the whole file at once (slurm mode);
                #   -i:    edit file in place;
                #   -p:    loop over the input + print the result;
                #   -e:    execute supplied Perl code;
                #
                # regex modifiers at the end:
                #   s: single-line mode, makes '.' match newline characters;
                #   m: multi-line mode: makes ^ and $ match the beginning and end of individual lines;
                #   g: global mode: replace all instances of the same certificate
                /usr/bin/perl -0777 -i -pe 's/(?:^(?!---)(?!\s*$)[^\n]*\n)*'"${BEGIN_CERT}"'\r?\n'"${cert_pattern}"'.*?'"${END_CERT}"'\r?\n//smg' ${path}
                cert_removed=$?

                echo_and_append_to_log "[WARNING] Untrusted root cert with pattern '${cert_pattern}' removed from: ${path}"
                echo_and_append_to_log "Backup of $(basename ${path}) in ${parent_dir}: $(basename ${backup})"

                # restore read-only permissions if needed
                if [[ ${restore_dir_read_only} == "yes" ]]; then
                    echo_and_append_to_log ">> restoring read-only permissions on ${parent_dir} ..."
                    chmod u-w ${parent_dir}
                    if [[ $? -ne 0 ]]; then
                        fail "Restoring read-only permissions on ${parent_dir} failed, giving up..."
                    fi
                fi
                if [[ ${restore_file_read_only} == "yes" ]]; then
                    echo_and_append_to_log ">> restoring read-only permissions on ${path} ..."
                    chmod u-w ${path}
                    if [[ $? -ne 0 ]]; then
                        fail "Restoring read-only permissions on ${path} failed, giving up..."
                    fi
                fi

                if [[ ${cert_removed} -ne 0 ]]; then
                    fail "removing untrusted root cert from ${path} failed, giving up!"
                fi
            fi
        else
            fail "Unknown type of file: $(basename ${path})"
        fi
    fi
}
export -f remove_untrusted_root_cert

if [[ $# -eq 0 ]]; then
    fail "Usage: $0 <EasyBuild installation prefix, path to {software,modules} or generic path with *-full modes>"
fi
PREFIX=$1
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scan)
            MODE="SCAN"
            shift
            ;;
        --remove)
            MODE="REMOVE"
            shift
            ;;
        --scan-full)
            TYPE="FULL"
            MODE="SCAN"
            shift
            ;;
        --remove-full)
            TYPE="FULL"
            MODE="REMOVE"
            shift
            ;;
        --verbose|-v)
            VERBOSE="yes"
            shift
            ;;
        --help)
            /usr/bin/echo "Usage: $0 <path to software & modules> [--scan|--scan-full] [--remove|--remove-full] [--verbose]"
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            ;;
    esac
done

echo_and_append_to_log ">> path: ${PREFIX}, mode: ${MODE}, type: ${TYPE}, verbose: ${VERBOSE}"

if [[ ${MODE} != "SCAN" ]] && [[ ${MODE} != "REMOVE" ]]; then
    fail "Mode not specified, use --scan or --scan-full or --remove or --remove-full"
fi

if [[ ${TYPE} == "PATTERN" ]]; then
    if [[ ! -d ${PREFIX}/software ]] || [[ ! -d ${PREFIX}/modules ]]; then
        echo_and_append_to_log "[WARNING] Pattern-based scanning is only supported for EasyBuild installations"
        fail "${PREFIX} does not have a 'software' and 'modules' subdirectory"
    fi
fi


known_path_patterns_pem=(
    "ABAQUS/*/cae/linux*/tools/SMApy/python*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "aiohttp/*/lib/python*/site-packages/botocore/cacert.pem"
    "Ansys/*/*/*/commonfiles/CPython/*/linx*/Release/python/lib/python*/site-packages/certifi/cacert.pem"
    "Ansys/*/*/*/commonfiles/CPython/*/linx*/Release/python/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/*/commonfiles/CPython/*/linx*/Release/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/*/rocky/bin/certifi/cacert.pem"
    "Ansys/*/*/CEI/apex*/machines/linux*/Python*/lib/python*/site-packages/botocore/cacert.pem"
    "Ansys/*/*/CEI/apex*/machines/linux*/Python*/lib/python*/site-packages/certifi/cacert.pem"
    "Ansys/*/*/CEI/apex*/machines/linux*/Python*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/CEI/apex*/machines/linux*/Python*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/CFD-Post/tools/gRPC*/linx64/grpc/share/grpc/roots.pem"
    "Ansys/*/*/CFD-Post/tools/gRPC*/linx64/grpc_base/share/grpc/roots.pem"
    "Ansys/*/*/CFX/tools/gRPC*/linx64/grpc/share/grpc/roots.pem"
    "Ansys/*/*/CFX/tools/gRPC*/linx64/grpc_base/share/grpc/roots.pem"
    "Ansys/*/*/commonfiles/CFX/tools/gRPC*/linx64/grpc/share/grpc/roots.pem"
    "Ansys/*/*/commonfiles/CFX/tools/gRPC*/linx64/grpc_base/share/grpc/roots.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx*/Release/Ansys/PyGeometry/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx*/Release/Ansys/PyOptislang/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyDPF/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyDPF/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyFluentCore/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyFluentCore/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyFluentVisual/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyFluentVisual/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyGeometry/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PyPrimeMesh/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/Ansys/PySimAI/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/python/lib/python*/site-packages/certifi/cacert.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/python/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/commonfiles/CPython/*/linx64/Release/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/dcs/lib/certifi/cacert.pem"
    "Ansys/*/*/dcs/lib/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/meshing/site/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/PyDPF-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/PyDPF-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/PyFluentCore-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/PyFluentCore-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/PySimAI-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/python*/saf-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/python*/saf-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/python*/site-packages/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/optiSLang/lib/python*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/scripting/algorithms/DLE/lib/python*/site-packages/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/scripting/algorithms/DLE/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/scripting/algorithms/DX_env/lib/site-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/optiSLang/scripting/algorithms/FFNet_env/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/optiSLang/scripting/algorithms/stochos_env/lib/python*/site-packages/certifi/cacert.pem"
    "Ansys/*/*/optiSLang/scripting/algorithms/stochos_env/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Ansys/*/*/optiSLang/scripting/algorithms/stochos_env/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/python*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Ansys/*/*/TurboGrid/tools/gRPC*/linx64/grpc/share/grpc/roots.pem"
    "Ansys/*/*/TurboGrid/tools/gRPC*/linx64/grpc_base/share/grpc/roots.pem"
    "Ansys/*/*/TurboGrid/tools/gRPC*/linx64/grpc_base/share/grpc/roots.pen"
    "awscli/*/lib/python*/site-packages/awscli/botocore/cacert.pem"
    "awscli/*/lib/python*/site-packages/botocore/cacert.pem"
    "Blender/*/*/python/lib/python*/site-packages/certifi/cacert.pem"
    "Blender/*/*/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "boto3/*/lib/python*/site-packages/botocore/cacert.pem"
    "ccp4/*/ccp4-*/coot_py3/etc/ssl/cacert.pem"
    "ccp4/*/ccp4-*/coot_py3/lib/python*/site-packages/certifi/cacert.pem"
    "ccp4/*/ccp4-*/coot_py3/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "ccp4/*/ccp4-*/etc/ssl/cacert.pem"
    "ccp4/*/ccp4-*/lib/python*/site-packages/certifi/cacert.pem"
    "ccp4/*/ccp4-*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "ccp4/*/ccp4-*/lib/python*/site-packages/requests/cacert.pem"
    "ccpem-doppio/*/envs/*/lib/python*/site-packages/certifi/cacert.pem"
    "ccpem-doppio/*/envs/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "ccpem-doppio/*/envs/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "ccpem-doppio/*/envs/*/ssl/cacert.pem"
    "ccpem-doppio/*/lib/python*/site-packages/certifi/cacert.pem"
    "ccpem-doppio/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "ccpem-doppio/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "ccpem-doppio/*/pkgs/certifi-*/site-packages/certifi/cacert.pem"
    "ccpem-doppio/*/pkgs/pip-*/site-packages/pip/_vendor/certifi/cacert.pem"
    "ccpem-doppio/*/ssl/cacert.pem"
    "CellRanger-ARC/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "cellranger-arc/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "CellRanger-ARC/*/external/anaconda/ssl/cacert.pem"
    "cellranger-arc/*/external/anaconda/ssl/cacert.pem"
    "cellranger-atac/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "cellranger-atac/*/external/anaconda/ssl/cacert.pem"
    "cellranger-atac/*/miniconda-atac-cs/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "cellranger-atac/*/miniconda-atac-cs/*/lib/python*/site-packages/pip/_vendor/requests/cacert.pem"
    "cellranger-atac/*/miniconda-atac-cs/*/lib/python*/site-packages/requests/cacert.pem"
    "cellranger-atac/*/miniconda-atac-cs/*/ssl/cacert.pem"
    "CellRanger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "cellranger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "CellRanger/*/external/anaconda/ssl/cacert.pem"
    "cellranger/*/external/anaconda/ssl/cacert.pem"
    "CellRanger/*/external/anaconda/ssl/cert.pem"
    "cellranger/*/external/anaconda/ssl/cert.pem"
    "cellranger/*/miniconda-cr-cs/*/lib/python*/site-packages/pip/_vendor/requests/cacert.pem"
    "cellranger/*/miniconda-cr-cs/*/lib/python*/site-packages/requests/cacert.pem"
    "cellranger/*/miniconda-cr-cs/*/ssl/cacert.pem"
    "cellranger/*/miniconda-cr-cs/*/ssl/cert.pem"
    "concoct/*/lib/python*/site-packages/certifi-*/certifi/cacert.pem"
    "concoct/*/lib/python*/site-packages/certifi-*/certifi/weak.pem"
    "crYOLO/*/lib/python*/site-packages/certifi/cacert.pem"
    "crYOLO/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "crYOLO/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "crYOLO/*/ssl/cacert.pem"
    "CryoSPARC/*/cryosparc_*/.pixi/envs/*/lib/python3.12/site-packages/certifi/cacert.pem"
    "CryoSPARC/*/cryosparc_*/.pixi/envs/*/ssl/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/envs/cryosparc_*/lib/python*/site-packages/certifi/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/envs/cryosparc_*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/envs/cryosparc_*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/envs/cryosparc_*/ssl/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/pkgs/ca-certificates-*/ssl/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/pkgs/certifi-*/site-packages/certifi/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/pkgs/pip-*/site-packages/pip/_vendor/certifi/cacert.pem"
    "CryoSPARC/*/cryosparc_*/deps/anaconda/ssl/cacert.pem"
    "cryosparc2_worker/*/deps/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "cryosparc2_worker/*/deps/anaconda/lib/python*/site-packages/pip/_vendor/requests/cacert.pem"
    "cryosparc2_worker/*/deps/anaconda/pkgs/ca-certificates-*/ssl/cacert.pem"
    "cryosparc2_worker/*/deps/anaconda/pkgs/certifi-*/lib/python*/site-packages/certifi/cacert.pem"
    "cryosparc2_worker/*/deps/anaconda/pkgs/certifi-*/lib/python*/site-packages/certifi/weak.pem"
    "cryosparc2_worker/*/deps/anaconda/pkgs/pip-*/lib/python*/site-packages/pip/_vendor/requests/cacert.pem"
    "cryosparc2_worker/*/deps/anaconda/ssl/cacert.pem"
    "cryosparc_worker/*/cryosparc_worker/.pixi/envs/worker/lib/python*/site-packages/certifi/cacert.pem"
    "cryosparc_worker/*/cryosparc_worker/.pixi/envs/worker/ssl/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/envs/cryosparc_worker_env/lib/python*/site-packages/certifi/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/envs/cryosparc_worker_env/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "cryosparc_worker/*/deps/anaconda/envs/cryosparc_worker_env/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/envs/cryosparc_worker_env/ssl/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/pkgs/ca-certificates-*/ssl/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/pkgs/certifi-*/lib/python*/site-packages/certifi/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/pkgs/pip-*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "cryosparc_worker/*/deps/anaconda/ssl/cacert.pem"
    "CUDA/*/nsight-compute-*/host/target-linux-x64/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "CUDA/*/nsight-systems-*/host-linux-x64/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "CUDA/*/nsight-systems-*/target-linux-x64/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "cwltool/*/lib/python*/site-packages/certifi-*/certifi/cacert.pem"
    "cwltool/*/lib/python*/site-packages/certifi-*/certifi/weak.pem"
    "dotNET-Core/*/sdk/*/trustedroots/codesignctl.pem"
    "dotNET-Core/*/sdk/*/trustedroots/timestampctl.pem"
    "dotNET-SDK/*/sdk/*/trustedroots/codesignctl.pem"
    "dotNET-SDK/*/sdk/*/trustedroots/timestampctl.pem"
    "Eclipse/*/macros/_internal/certifi/cacert.pem"
    "EMAN2/*/lib/python*/site-packages/certifi/cacert.pem"
    "EMAN2/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "EMAN2/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "EMAN2/*/pkgs/certifi-*/lib/python*/site-packages/certifi/cacert.pem"
    "EMAN2/*/pkgs/pip-*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "EMAN2/*/ssl/cacert.pem"
    "empiar_depositor/*/lib/python*/site-packages/certifi/cacert.pem"
    "flit/*/lib/python*/site-packages/certifi/cacert.pem"
    "FreeSurfer/*/python/lib/python*/site-packages/certifi/cacert.pem"
    "FreeSurfer/*/python/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "FreeSurfer/*/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/envs/fslpython/lib/python*/site-packages/botocore/cacert.pem"
    "FSL/*/fsl/fslpython/envs/fslpython/lib/python*/site-packages/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/envs/fslpython/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/envs/fslpython/ssl/cacert.pem"
    "FSL/*/fsl/fslpython/lib/python*/site-packages/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/pkgs/botocore*/site-packages/botocore/cacert.pem"
    "FSL/*/fsl/fslpython/pkgs/ca-certificates*/ssl/cacert.pem"
    "FSL/*/fsl/fslpython/pkgs/certifi*/lib/python*/site-packages/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/pkgs/certifi*/site-packages/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/pkgs/pip*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/pkgs/pip*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/fsl/fslpython/ssl/cacert.pem"
    "FSL/*/lib/python*/site-packages/awscli/botocore/cacert.pem"
    "FSL/*/lib/python*/site-packages/botocore/cacert.pem"
    "FSL/*/lib/python*/site-packages/certifi/cacert.pem"
    "FSL/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/share/grpc/roots.pem"
    "FSL/*/ssl/cacert.pem"
    "GC3Pie/*/lib/python*/site-packages/pip-*/pip/_vendor/requests/cacert.pem"
    "GC3Pie/*/lib/python*/site-packages/requests-*/requests/cacert.pem"
    "gcloud/*/lib/third_party/botocore/cacert.pem"
    "gcloud/*/lib/third_party/certifi/cacert.pem"
    "gcloud/*/platform/bq/third_party/certifi/cacert.pem"
    "gcloud/*/platform/bundledpythonunix/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "gcloud/*/platform/bundledpythonunix/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "gcloud/*/platform/gsutil/third_party/certifi/certifi/cacert.pem"
    "gimmemotifs/*/lib/python*/site-packages/certifi/cacert.pem"
    "gRPC/*/share/grpc/roots.pem"
    "grpcio/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "ilastik/*/lib/python*/site-packages/certifi/cacert.pem"
    "ilastik/*/lib/python*/site-packages/pip/_vendor/requests/cacert.pem"
    "ilastik/*/ssl/cacert.pem"
    "ilastik/*/ssl/cert.pem"
    "intel-compilers/*/compiler/*/linux/lib/oclfpga/host/linux64/bin/perl/lib/site_perl/*/Mozilla/CA/cacert.pem"
    "intel-compilers/*/compiler/*/opt/oclfpga/host/linux64/bin/perl/lib/site_perl/*/Mozilla/CA/cacert.pem"
    "intel-compilers/*/debugger/*/dep/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "intel-compilers/*/debugger/*/opt/debugger/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "IPython/*/lib/python*/site-packages/certifi-*/certifi/cacert.pem"
    "IPython/*/lib/python*/site-packages/certifi-*/certifi/weak.pem"
    "IPython/*/lib/python*/site-packages/requests-*/requests/cacert.pem"
    "Julia/*/share/julia/cert.pem"
    "Julia/*linux-x86_64/share/julia/cert.pem"
    "jupyterhub/*/lib/python*/site-packages/certifi-*/certifi/cacert.pem"
    "LocScale/*/lib/python*/site-packages/locscale/emmernet/emmernet_models/ccp*/etc/ssl/cacert.pem"
    "LocScale/*/lib/python*/site-packages/locscale/emmernet/emmernet_models/ccp*/lib/python*/site-packages/certifi/cacert.pem"
    "LocScale/*/lib/python*/site-packages/locscale/emmernet/emmernet_models/ccp*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "LocScale/*/lib/python*/site-packages/locscale/emmernet/emmernet_models/ccp*/lib/python*/site-packages/requests/cacert.pem"
    "Mamba/*/lib/python*/site-packages/certifi/cacert.pem"
    "Mamba/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Mamba/*/pkgs/botocore-*/site-packages/botocore/cacert.pem"
    "Mamba/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "Mamba/*/pkgs/certifi-*/site-packages/certifi/cacert.pem"
    "Mamba/*/pkgs/libgrpc*/share/grpc/roots.pem"
    "Mamba/*/pkgs/pip-*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Mamba/*/ssl/cacert.pem"
    "Maple/*/Python.*/lib/python*/site-packages/certifi/cacert.pem"
    "Maple/*/Python.*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Maple/*/Python.*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Mathematica/*/SystemFiles/Components/CURLLinkResources/cacert.pem"
    "Mathematica/*/SystemFiles/Links/CURLLink/SSL/cacert.pem"
    "Mathematica/*/SystemFiles/Links/CURLLink/SSL/cacert.pem"
    "MATLAB/*/sys/certificates/ca/rootcerts.pem"
    "MCR/*/*/sys/certificates/ca/rootcerts.pem"
    "Miniconda3/*/lib/python*/site-packages/certifi/cacert.pem"
    "Miniconda3/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniconda3/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "Miniconda3/*/pkgs/certifi-*/lib/python*/site-packages/certifi/cacert.pem"
    "Miniconda3/*/pkgs/pip-*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniconda3/*/pkgs/r-rcurl-*/lib/R/library/RCurl/CurlSSL/cacert.pem"
    "Miniconda3/*/ssl/cacert.pem"
    "Miniforge3/*/lib/python*/site-packages/certifi/cacert.pem"
    "Miniforge3/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniforge3/*/pkgs/awscli*/lib/python*/site-packages/awscli/botocore/cacert.pem"
    "Miniforge3/*/pkgs/botocore*/site-packages/botocore/cacert.pem"
    "Miniforge3/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "Miniforge3/*/pkgs/certifi-*/site-packages/certifi/cacert.pem"
    "Miniforge3/*/pkgs/dotnet-sdk-*/lib/dotnet/sdk/*/trustedroots/codesignctl.pem"
    "Miniforge3/*/pkgs/dotnet-sdk-*/lib/dotnet/sdk/*/trustedroots/timestampctl.pem"
    "Miniforge3/*/pkgs/libgrpc*/share/grpc/roots.pem"
    "Miniforge3/*/pkgs/pip-*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniforge3/*/ssl/cacert.pem"
    "MoBIE_cmd/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "MoBIE_cmd/*/ssl/cacert.pem"
    "MoBIE_utils/*/lib/python*/site-packages/botocore/cacert.pem"
    "MoBIE_utils/*/lib/python*/site-packages/certifi/cacert.pem"
    "MoBIE_utils/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "MoBIE_utils/*/ssl/cacert.pem"
    "MultiQC/*/lib/python*/site-packages/botocore/cacert.pem"
    "MultiQC/*/lib/python*/site-packages/certifi/cacert.pem"
    "onedep_api/*/lib/python*/site-packages/certifi/cacert.pem"
    "PDM/*/lib/python*/site-packages/certifi/cacert.pem"
    "Perl-bundle-CPAN/*/lib/perl5/site_perl/*/Mozilla/CA/cacert.pem"
    "Perl/*/lib/perl5/site_perl/*/Mozilla/CA/cacert.pem"
    "phenix/*/lib/python*/site-packages/certifi/cacert.pem"
    "phenix/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "phenix/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "phenix/*/phenix-*/base/lib/python*/site-packages/certifi/cacert.pem"
    "phenix/*/phenix-*/base/lib/python*/site-packages/certifi/weak.pem"
    "phenix/*/phenix-*/base/lib/python*/site-packages/pip/_vendor/requests/cacert.pem"
    "phenix/*/phenix-*/conda_base/lib/python*/site-packages/certifi/cacert.pem"
    "phenix/*/phenix-*/conda_base/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "phenix/*/phenix-*/conda_base/ssl/cacert.pem"
    "phenix/*/share/grpc/roots.pem"
    "phenix/*/ssl/cacert.pem"
    "pip/*/lib/python*/site-packages/pip-*/pip/_vendor/requests/cacert.pem"
    "poetry/*/lib/python*/site-packages/certifi/cacert.pem"
    "Python-bundle-PyPI/*/lib/python*/site-packages/certifi/cacert.pem"
    "Python/*/lib/python*/site-packages/certifi*/certifi/cacert.pem"
    "Python/*/lib/python*/site-packages/certifi/cacert.pem"
    "Python/*/lib/python*/site-packages/pip*/pip/_vendor/certifi/cacert.pem"
    "Python/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "PyTorch-Lightning/*/lib/python*/site-packages/botocore/cacert.pem"
    "QIIME2/*/lib/python*/site-packages/certifi/cacert.pem"
    "QIIME2/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "QIIME2/*/lib/R/library/RCurl/CurlSSL/cacert.pem"
    "QIIME2/*/ssl/cacert.pem"
    "R-bundle-CRAN/*/RCurl/CurlSSL/cacert.pem"
    "R-bundle-CRAN/*/rsconnect/cert/cacert.pem"
    "R/*/lib*/R/library/openssl/cacert.pem"
    "R/*/lib*/R/library/RCurl/CurlSSL/cacert.pem"
    "R/*/lib*/R/library/rsconnect/cert/cacert.pem"
    "R/*/lib*/R/library/synapseClient/certificateBundle/cacert.pem"
    "ReFrame/*/external/x86_64/certifi/cacert.pem"
    "ReFrame/*/local/lib/python*/dist-packages/pip-*/pip/_vendor/certifi/cacert.pem"
    "requests/*/lib/python*/site-packages/requests-*/requests/cacert.pem"
    "Roary/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Roary/*/ssl/cacert.pem"
    "Ruby/*/lib/ruby/gems/*/gems/pusher-client-*/certs/cacert.pem"
    "slamdunk/*/lib/python*/site-packages/certifi/cacert.pem"
    "slamdunk/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "slamdunk/*/lib/R/library/openssl/cacert.pem"
    "slamdunk/*/ssl/cacert.pem"
    "SMRT-Link/*/install/smrtlink-release_*/bundles/smrttools/install/smrttools-release_*/private/thirdparty/awscli/awscli_*/*/*/dist/awscli/botocore/cacert.pem"
    "SMRT-Link/*/install/smrtlink-release_*/bundles/smrttools/install/smrttools-release_*/private/thirdparty/python3/python3_*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "SMRT-Link/*/install/smrtlink-release_*/bundles/smrttools/install/smrttools-release_*/private/thirdparty/python3pkgs/botocore-py3/botocore-py3_*/lib/python*/site-packages/botocore/cacert.pem"
    "SMRT-Link/*/install/smrtlink-release_*/bundles/smrttools/install/smrttools-release_*/private/thirdparty/python3pkgs/certifi-py3/certifi-py3_*/lib/python*/site-packages/certifi/cacert.pem"
    "snakemake/*/lib/python*/site-packages/certifi-*/certifi/cacert.pem"
    "snakemake/*/lib/python*/site-packages/certifi-*/certifi/weak.pem"
    "snakemake/*/lib/python*/site-packages/requests-*/requests/cacert.pem"
    "snakemake/*/lib/python/site-packages/certifi/cacert.pem"
    "spaceranger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "SpaceRanger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "SpaceRanger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "spaceranger/*/external/anaconda/ssl/cacert.pem"
    "SpaceRanger/*/external/anaconda/ssl/cacert.pem"
    "SpaceRanger/*/external/anaconda/ssl/cert.pem"
    "STAR-CCM+/*/*/STAR-CCM+*/star/lib/python/lib/python*/site-packages/certifi/cacert.pem"
    "tensorboard/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "TensorFlow/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "toil/*/lib/python*/site-packages/certifi-*/certifi/cacert.pem"
    "toil/*/lib/python*/site-packages/certifi-*/certifi/weak.pem"
    "toil/*/lib/python*/site-packages/websocket_client-*g/websocket/cacert.pem"
    "UMI-tools/*/lib/python*/site-packages/certifi/cacert.pem"
    "UMI-tools/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "UMI-tools/*/ssl/cacert.pem"
    "warp/*/lib/dotnet/sdk/*/trustedroots/codesignctl.pem"
    "warp/*/lib/dotnet/sdk/*/trustedroots/timestampctl.pem"
    "warp/*/lib/python*/site-packages/certifi/cacert.pem"
    "warp/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "warp/*/ssl/cacert.pem"
)
known_path_patterns_crt=(
    "Aspera-CLI/*/etc/curl-ca-bundle.crt"
    "Aspera-Connect/*/etc/curl-ca-bundle.crt"
    "Miniconda3/*/pkgs/r-rcurl-*/lib/R/library/RCurl/etc/ca-bundle.crt"
    "ont-guppy/*/data/certs-bundle.crt"
    "Pluto/*/packages/OpenSSL/test/certs/ca-certificates.crt"
    "QIIME2/*/lib/R/library/RCurl/etc/ca-bundle.crt"
    "R-bundle-CRAN/*/RCurl/etc/ca-bundle.crt"
    "R/*/lib64/R/library/RCurl/etc/ca-bundle.crt"
    "texlive/*/tlpkg/installer/curl/curl-ca-bundle.crt"
)

cnt=0

function check_path() {
    local path=$1
    local found=0
    for cert_pattern in ${UNTRUSTED_ROOT_CERT_PATTERNS[@]}; do

        echo_and_append_to_log ">> checking '${cert_pattern}' in $path"

        /usr/bin/grep "${cert_pattern}" "${path}" > /dev/null
        grep_ec=$?
        if [[ ${grep_ec} -eq 0 ]]; then
            echo_and_append_to_log "[ERROR] Untrusted root cert with pattern '${cert_pattern}' found in: ${path}"
            found=1
            remove_untrusted_root_cert "${cert_pattern}" "${path}"
        else
            echo_and_append_to_log "[OK] Untrusted root cert with pattern '${cert_pattern}' not found in ${path}"
        fi
    done
    if [[ ${found} -eq 1 ]]; then
        cnt=$((cnt + 1))
        echo_and_append_to_log ">> found ${cnt} paths with untrusted root cert so far..."
    fi
}
export -f check_path



if [[ ${TYPE} == "PATTERN" ]]; then
    echo_and_append_to_log "\n>> [INFO] checking .pem files with known patterns in ${PREFIX}/software ---------------------"
    for known_path_pattern in ${known_path_patterns_pem[@]}; do
        echo_and_append_to_log "\n>> [INFO] checking ${known_path_pattern}"...
        for path in $(ls -d ${PREFIX}/software/${known_path_pattern} 2>/dev/null); do
            check_path "${path}"
        done
    done
    echo_and_append_to_log "\n>> [INFO] checking .crt files with known patterns in ${PREFIX}/software ---------------------"
    for known_path_pattern in ${known_path_patterns_crt[@]}; do
        echo_and_append_to_log "\n>> [INFO] checking ${known_path_pattern}"...
        for path in $(ls -d ${PREFIX}/software/${known_path_pattern} 2> /dev/null); do
            check_path "${path}"
        done
    done
elif [[ ${TYPE} == "FULL" ]]; then
    echo_and_append_to_log "\n>> [INFO] checking all .pem files in ${PREFIX} (using find) ---------------------"
    for path in $(/usr/bin/find ${PREFIX} -type f -name "*.pem" 2> /dev/null); do
        check_path "${path}"
    done
    echo_and_append_to_log "\n>> [INFO] checking all .crt files in ${PREFIX} (using find) ---------------------"
    for path in $(/usr/bin/find ${PREFIX} -type f -name "*.crt" 2> /dev/null); do
        check_path "${path}"
    done
fi

if [[ ${cnt} -gt 0 ]]; then
    if [[ ${MODE} == "REMOVE" ]]; then
        echo_and_append_to_log "\n\n[WARNING] Untrusted root certificate removed from ${cnt} files\nYou should run again with --scan now...\n\n"
        exit 0
    else
        if [[ ${TYPE} == "FULL" ]]; then
            fail "Untrusted root certificate found ${cnt} times, but not removed, re-run with --remove-full to fix!"
        else
            fail "Untrusted root certificate found ${cnt} times, but not removed, re-run with --remove to fix!"
        fi
    fi
else
    echo_and_append_to_log "\n\n[OK] No files with untrusted root certificate, but maybe it's still hiding in other places...\n"
    echo_and_append_to_log "[OK] You can run a recursive scan for all *.pem and *.crt files using the --scan-full and --remove-full modes (but this may take a long time)\n\n"
fi

if [[ ${MODE} == "MODE" ]] && [[ ${cnt} -gt 0 ]]; then
    echo_and_append_to_log "\n>> [INFO] You may want to clean up the backup files that have been created, use:\n\n    find ${PREFIX} -name '*.${BACKUP_TAG}*'"
fi

echo_and_append_to_log ">> [INFO] end time: $(date)"

echo -e "\n>> all changed paths logged to ${LOGFILE}"
