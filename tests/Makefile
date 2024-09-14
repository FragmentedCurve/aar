AAR=../aar
KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
TESTS != ls *.sh

all:
.for t in ${TESTS}
	@KEY=${KEY} AAR=${AAR} TEST=${t:T:R} sh ${t} > /dev/null && echo ${t} passed. || echo ${t} failed.
	@rm -f *.tmp
.endfor

.PHONY: all
