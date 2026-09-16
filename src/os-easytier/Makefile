PKG_NAME?=os-easytier
VERSION?=1.1.3
ABI?=native

.PHONY: package clean
package:
	ABI="$(ABI)" PKG_NAME="$(PKG_NAME)" VERSION="$(VERSION)" sh ./build.sh
clean:
	rm -rf work dist
