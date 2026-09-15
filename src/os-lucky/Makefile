PKG_NAME?=	os-lucky
VERSION?=	1.1.2
ABI?=		native

.PHONY: package install clean

package:
	ABI="$(ABI)" PKG_NAME="$(PKG_NAME)" VERSION="$(VERSION)" ./build.sh

install: package
	pkg add -f "dist/$(PKG_NAME).pkg"

clean:
	rm -rf work/freebsd-pkg
