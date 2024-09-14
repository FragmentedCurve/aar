#!/bin/sh

set -e

OUT=${TEST}.out
IN=${TEST}.in
TMP=${TEST}.tmp

cp $IN $TMP
${AAR} -k ${KEY} decrypt $TMP
cmp $OUT $TMP
