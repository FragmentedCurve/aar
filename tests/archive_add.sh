#!/bin/sh

set -e

OUT=${TEST}.out
TMP=${TEST}.tmp

${AAR} -k ${KEY} -a ${TMP} new
${AAR} -k ${KEY} -a ${TMP} add ${TEST}.1.in foo
${AAR} -k ${KEY} -a ${TMP} add ${TEST}.2.in bar
${AAR} -k ${KEY} -a ${TMP} add ${TEST}.3.in

cmp $OUT $TMP
