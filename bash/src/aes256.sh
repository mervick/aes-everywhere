#!/usr/bin/env bash
# aes256.sh
# This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
#
# This is an implementation of the AES algorithm, specifically CBC mode,
# with 256 bits key length and PKCS7 padding.
#
# Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
# Licensed under the MIT license
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

c='\033[0m'
b='\033[1m'

help="$(cat << EOF
${b}NAME${c}
    aes256 - aes 256 algorithm (the part of cross-language-encryption library)

${b}SYNOPSIS${c}
    ${b}aes256${c} [encrypt|decrypt] [${b}-p${c} passphrase|${b}--passphrase${c}=passphrase]
    [${b}-i${c} input_file|${b}--in${c}=input_file] [${b}-o${c} output_file|${b}--out${c}=output_file]

${b}DESCRIPTION${c}
    ${b}aes256${c} is part of cross-language-encryption library and provide function
    for encrypt and decrypt strings or files

    Options:

    ${b}-p${c} passphrase
    ${b}--passphrase=${c}passphrase
        Specifies passphrase

    ${b}-i${c} input_file
    ${b}--in=${c}input_file
        Specifies input file for encrypt or decrypt

    ${b}-o${c} output_file
    ${b}--out=${c}output_file
        Specifies output file where will be stored result

    ${b}--help${c}
        Show this help

${b}AUTHORS${c}
    Cross language encryption library is released by Andrey Izman (c) 2018.
EOF
)"

usage="$(cat << EOF
usage: aes256 encrypt|decrypt [-p passphrase|--passphrase=passphrase]
       [-i input_file|--in=input_file] [-o output_file|--out=output_file]
EOF
)"

in=""
out=""

if [[ $# -eq 0 ]]; then
    (1>&2 echo "Invalid count of options")
    echo -e "$usage"
    exit 7
fi

operation="encrypt"

if [[ $1 == "decrypt" ]]; then
    operation="decrypt"
    shift
elif [[ $1 == "encrypt" ]]; then
    shift
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p)
            shift
            if [[ $# -gt 0 ]]; then
                passphrase="$1"
            else
                (1>&2 echo "Require passphrase")
                exit 2
            fi
        ;;

        --passphrase=*)
            passphrase="${1#--passphrase=*}"
        ;;

        -i)
            shift
            if [[ $# -gt 0 ]]; then
                in="$1"
            else
                (1>&2 echo "Require input")
                exit 3
            fi
        ;;

        --in=*)
            in="${1#--input=*}"
        ;;

        -o)
            shift
            if [[ $# -gt 0 ]]; then
                out="$1"
            else
                (1>&2 echo "Require out")
                exit 4
            fi
        ;;

        --out=*)
            out="${1#--out=*}"
        ;;

        --help)
            echo -e "$help"
            exit 0
        ;;

        *)
            (1>&2 echo "Unknown option '${1}'")
            echo -e "$usage"
            exit 1
        ;;
    esac
    shift
done

STDIN=""
if [[ "$in" == "" ]]; then
    if readlink /proc/$$/fd/0 | grep -q "^pipe:"; then
        STDIN="$(cat)"
    fi
elif [[ ! -f "$in" ]]; then
    (1>&2 echo "Unable to open '${in}'")
    exit 8
else
    in="$(cat "$in")"
fi

if [[ "$operation" == "decrypt" ]]; then
    if [[ "$in" == "" ]]; then
        in="$STDIN"
    fi

    result="$(echo -n "$in" | openssl enc -aes-256-cbc -md md5 -a -A -pass "pass:${passphrase}" -d)"

else
    if [[ "$in" == "" ]]; then
        result="$(echo -n "$STDIN" | openssl enc -aes-256-cbc -md md5 -a -A -pass "pass:${passphrase}")"
    else
        result="$(openssl enc -aes-256-cbc -md md5 -a -A -pass "pass:${passphrase}" -in "$in")"
    fi
fi

if [[ "$out" == "" ]]; then
    echo -n "$result"
else
    echo -n "$result" > "$out"
fi
