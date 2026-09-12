VERSION?= 1.1.0
ABI?= FreeBSD:15:amd64

.PHONY: package clean
package:
	ABI="$(ABI)" VERSION="$(VERSION)" sh ./build.sh

clean:
	rm -rf work/freebsd-pkg
