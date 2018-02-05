#!/usr/bin/env bash
# aes256.sh
# AES Everywhere - Cross Language Encryption Library
# author Andrey Izman <izmanw@gmail.com>
# copyright Andrey Izman (c) 2018
# license MIT

c='\033[0m'
b='\033[1m'

help="$(cat << EOF
${b}NAME${c}
    aes256 - aes 256 algorithm (the part of cross-language-encryption library)

${b}SYNOPSIS${c}
    ${b}aes256${c} [encrypt|decrypt] [${b}-p${c} passphrase|${b}--passphrase${c}=passphrase]
    [${b}-i${c} input_file|${b}--in${c}=input_file] [${b}-o${c} output_file|${b}--out${c}=output_file]
    [${b}-f${c} format|${b}--format${c}=format]

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

    ${b}-f${c} format
    ${b}--format=${c}format
        Specifies the format, can be ${b}concat${c} or ${b}json${c}

    ${b}--help${c}
        Show this help

${b}AUTHORS${c}
    Cross language encryption library is released by Andrey Izman (c) 2018.
EOF
)"

usage="$(cat << EOF
usage: aes256 encrypt|decrypt [-p passphrase|--passphrase=passphrase]
       [-i input_file|--in=input_file] [-o output_file|--out=output_file]
       [-f format|--format=format]
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
format="concat"

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

        -f)
            shift
            if [[ $# -gt 0 ]]; then
                format="$1"
            else
                (1>&2 echo "Require format")
                exit 4
            fi
        ;;

        --format=*)
            format="${1#--format=*}"
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

if [[ "$format" != "json" && "$format" != "concat" ]]; then
    (1>&2 echo "Unsupported format '$format'")
    exit 9
fi

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
