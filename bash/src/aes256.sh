#!/usr/bin/env bash
# aes256.sh
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

    iv=""; salt=""; ct=""

    if [[ "$format" == "json" ]]; then
        ct="$(echo -n "$in" | sed -s 's/^.*"ct":"\([^"]*\)".*$/\1/')"
        iv="$(echo -n "$in" | sed -s 's/^.*"iv":"\([^"]*\)".*$/\1/')"
        salt="$(echo -n "$in" | sed -s 's/^.*"s":"\([^"]*\)".*$/\1/' | xxd -r -p)"
    else
        ct="${in:48}"
        iv="${in:16:32}"
        salt="$(echo "${in:0:16}" | xxd -r -p)"
    fi

    concatenated="${passphrase}${salt}";
    md5_0="$(echo -n "$concatenated" | md5sum | sed -s 's/\s*-$//' | xxd -r -p)"
    salted="$md5_0"

    while [[ "${#salted}" -lt 32 ]]; do
        md5_1="$(echo -n "${md5_0}${concatenated}" | md5sum | sed -s 's/\s*-$//' | xxd -r -p)"
        salted="${salted}${md5_1}"
        md5_0="$md5_1"
    done

    key="${salted:0:32}"
    key="$(echo -n "$key" | xxd -p | tr -d '\n')"

    result="$(echo -n "$ct" | openssl enc -aes-256-cbc -nosalt -A -a -K "$key" -iv "$iv" -d)"

else # encrypt
    while true; do
        salt="$(openssl rand 12)"
        salt="${salt:0:8}"
        salted=""; dx=""

        while [[ "${#salted}" -lt 48 ]]; do
            dx="$(echo -n "${dx}${passphrase}${salt}" | md5sum | sed -s 's/\s*-$//' | xxd -r -p)"
            salted="${salted}${dx}"
        done

        key="${salted:0:32}"
        iv="${salted:32:16}"

        iv="$(echo -n "$iv" | xxd -p | tr -d '\n')"
        key="$(echo -n "$key" | xxd -p | tr -d '\n')"

        if [[ "${#iv}" != 32 || "${#key}" != 64 ]]; then
            continue
        fi

        break
    done

    if [[ "$in" == "" ]]; then
        ct="$(echo -n "$STDIN" | openssl enc -aes-256-cbc -nosalt -A -a -K "$key" -iv "$iv")"
    else
        ct="$(openssl enc -aes-256-cbc -nosalt -A -a -K "$key" -iv "$iv" -in "$in")"
    fi

    salt="$(echo -n "$salt" | xxd -p | tr -d '\n')"

    if [[ "$format" == "json" ]]; then
        result='{"ct":"'"$ct"'","iv":"'"$iv"'","s":"'"$salt"'"}';
    else
        result="${salt}${iv}${ct}"
    fi
fi

if [[ "$out" == "" ]]; then
    echo -n "$result"
else
    echo -n "$result" > "$out"
fi
