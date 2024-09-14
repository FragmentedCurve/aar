#!/bin/sh

# Bugs in base64 found by radamsa

! ${AAR} -k uNUvs/VIKgEW6jAIJ3DOUWYuZUtFiUFDk1ZWRJaRF4Y=cprfiedy -a ${TEST}.tmp new
! ${AAR} -k uNUvs/VIKgEW6jAIJ3DOUWYuZUtFiUFDk1ZWRJaRF4Y=rcdlpiyt -a ${TEST}.tmp new
! ${AAR} -k uNUvs/VIKgEW6jAIJ3DOUWYuZUtFiUFDk1ZWRJa=====         -a ${TEST}.tmp new
! ${AAR} -k AA==                                                 -a ${TEST}.tmp new
! ${AAR} -k AAAA                                                 -a ${TEST}.tmp new
! ${AAR} -k AAAAzzz=                                             -a ${TEST}.tmp new
! ${AAR} -k uNUvs/VIKgEW6jAIJ3DOUWYuZUtFiUFDk1ZWRJaRF4Yz         -a ${TEST}.tmp new
