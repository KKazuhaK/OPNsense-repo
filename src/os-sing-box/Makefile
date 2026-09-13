PKG_NAME?=	os-sing-box
VERSION?=	1.1.0
ABI?=		native

.PHONY: package install clean

package:
	ABI="$(ABI)" PKG_NAME="$(PKG_NAME)" VERSION="$(VERSION)" ./build.sh

install: package
	pkg add -f "dist/$(PKG_NAME)-$(VERSION).pkg"

clean:
	rm -rf work/freebsd-pkg
