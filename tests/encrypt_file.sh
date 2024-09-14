#!/bin/sh

set -e

OUT=${TEST}.out
IN=${TEST}.in
TMP=${TEST}.tmp

cp $IN $TMP
${AAR} -k ${KEY} encrypt $TMP
cmp $OUT $TMP
