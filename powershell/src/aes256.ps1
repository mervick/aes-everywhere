# aes256.ps1
# This file is part of AES-everywhere project (https://github.com/mervick/aes-everywhere)
#
# This is an implementation of the AES algorithm, specifically CBC mode,
# with 256 bits key length and PKCS7 padding.
#
# Copyright Andrey Izman (c) 2018-2019 <izmanw@gmail.com>
# Copyright Philip Mayer (c) 2020 <philip.mayer@shadowsith.de>
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

param (
    [String]$m="",
    [String]$t="",
    [String]$p="",
    [String]$i="",
    [String]$o="",
    [switch]$help,
    [switch]$h
)

$small_help = "usage: aes256 [-m encrypt (default)|decrypt] [-t text] [-p passphrase]
`t[-i input_file] [-o output_file]"

$help_text = "
NAME
`taes256 - aes 256 algorithm (the part of cross-language-encryption library) 

SYNOPSIS
`taes256 [-m encrypt(default)|decrypt] [-t text] [-p passphrase]
`t [-i input_file] [-o output_file]

DESCRIPTION
`taes256 is part of cross-language-encryption library and provide function
`tfor encrypt and decrypt strings or files

Options:
`t-p passphrase

Specifies passphrase
`t-i input_file

Specifies input file for encrypt or decrypt
`t-o output_file

Specifies output file where will be stored result
`t-h
`t-help
`tShow this help

AUTHORS
`tCross language encryption library is released by Andrey Izman (c) 2018.
`tPowershell support is released by Philip Mayer (c) 2020.
"

$cmd="& openssl enc -aes-256-cbc -md md5 -a -A -pass pass:$p"
if ($m -eq 'decrypt') {
    $cmd = "$cmd -d";
}

if ($p -ne '' ) {
    if ($t -ne '') {
        $cmd = "& echo $t | $cmd"
    }
    if ($i -ne '') {
        $cmd = "$cmd -in $i"
    }
    if ($o -ne '') {
        $cmd = "$cmd -out $o"
    }
    iex $cmd
}


# Print help
if ($help -or $h) {
    echo $help_text
} elseif ($m -eq '' -And $p -eq '' -And $i -eq '' -And $o -eq '') {
    echo $small_help
}