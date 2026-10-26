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
    "aiohttp/*/lib/python*/site-packages/botocore/cacert.pem"
    "boto3/*/lib/python*/site-packages/botocore/cacert.pem"
    "Blender/*/*/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Blender/*/*/python/lib/python*/site-packages/certifi/cacert.pem"
    "CellRanger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "CellRanger/*/external/anaconda/ssl/cacert.pem"
    "CUDA/*/nsight-compute-*/host/target-linux-x64/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "CUDA/*/nsight-systems-*/host-linux-x64/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "CUDA/*/nsight-systems-*/target-linux-x64/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "dotNET-Core/*/sdk/*/trustedroots/codesignctl.pem"
    "dotNET-Core/*/sdk/*/trustedroots/timestampctl.pem"
    "flit/*/lib/python*/site-packages/certifi/cacert.pem"
    "FreeSurfer/*/python/lib/python*/site-packages/certifi/cacert.pem"
    "FreeSurfer/*/python/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "FreeSurfer/*/python/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/lib/python*/site-packages/certifi/cacert.pem"
    "FSL/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "FSL/*/share/grpc/roots.pem"
    "FSL/*/ssl/cacert.pem"
    "gcloud/*/lib/third_party/certifi/cacert.pem"
    "gcloud/*/platform/gsutil/third_party/certifi/certifi/cacert.pem"
    "grpcio/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "gRPC/*/share/grpc/roots.pem"
    "intel-compilers/*/compiler/*/linux/lib/oclfpga/host/linux64/bin/perl/lib/site_perl/*/Mozilla/CA/cacert.pem"
    "intel-compilers/*/debugger/*/dep/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Julia/*linux-x86_64/share/julia/cert.pem"
    "Julia/*/share/julia/cert.pem"
    "Mamba/*/lib/python*/site-packages/certifi/cacert.pem"
    "Mamba/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Mamba/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "Mamba/*/pkgs/certifi-*/site-packages/certifi/cacert.pem"
    "Mamba/*/pkgs/pip-*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Mamba/*/ssl/cacert.pem"
    "Maple/*/Python.*/lib/python*/site-packages/certifi/cacert.pem"
    "Maple/*/Python.*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "Maple/*/Python.*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Mathematica/*/SystemFiles/Links/CURLLink/SSL/cacert.pem"
    "Mathematica/*/SystemFiles/Links/CURLLink/SSL/cacert.pem"
    "Miniconda3/*/lib/python*/site-packages/certifi/cacert.pem"
    "Miniconda3/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniconda3/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "Miniconda3/*/pkgs/certifi-*/lib/python*/site-packages/certifi/cacert.pem"
    "Miniconda3/*/pkgs/pip-*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniconda3/*/ssl/cacert.pem"
    "Miniforge3/*/lib/python*/site-packages/certifi/cacert.pem"
    "Miniforge3/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniforge3/*/pkgs/ca-certificates-*/ssl/cacert.pem"
    "Miniforge3/*/pkgs/certifi-*/site-packages/certifi/cacert.pem"
    "Miniforge3/*/pkgs/pip-*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Miniforge3/*/ssl/cacert.pem"
    "PDM/*/lib/python*/site-packages/certifi/cacert.pem"
    "Perl-bundle-CPAN/*/lib/perl5/site_perl/*/Mozilla/CA/cacert.pem"
    "Perl/*/lib/perl5/site_perl/*/Mozilla/CA/cacert.pem"
    "poetry/*/lib/python*/site-packages/certifi/cacert.pem"
    "Python-bundle-PyPI/*/lib/python*/site-packages/certifi/cacert.pem"
    "Python/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Python/*/lib/python*/site-packages/certifi/cacert.pem"
    "R-bundle-CRAN/*/RCurl/CurlSSL/cacert.pem"
    "R-bundle-CRAN/*/rsconnect/cert/cacert.pem"
    "ReFrame/*/external/x86_64/certifi/cacert.pem"
    "ReFrame/*/local/lib/python*/dist-packages/pip-*/pip/_vendor/certifi/cacert.pem"
    "R/*/lib/R/library/openssl/cacert.pem"
    "Roary/*/lib/python*/site-packages/pip/_vendor/certifi/cacert.pem"
    "Roary/*/ssl/cacert.pem"
    "Ruby/*/lib/ruby/gems/*/gems/pusher-client-*/certs/cacert.pem"
    "SpaceRanger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "SpaceRanger/*/external/anaconda/lib/python*/site-packages/certifi/cacert.pem"
    "SpaceRanger/*/external/anaconda/ssl/cacert.pem"
    "SpaceRanger/*/external/anaconda/ssl/cert.pem"
    "tensorboard/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
    "TensorFlow/*/lib/python*/site-packages/grpc/_cython/_credentials/roots.pem"
)
known_path_patterns_crt=(
    "Pluto/*/packages/OpenSSL/test/certs/ca-certificates.crt"
    "R-bundle-CRAN/*/RCurl/etc/ca-bundle.crt"
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
