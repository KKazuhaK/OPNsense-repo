VERSION?= 1.1.2
export TARGET_PROFILE TARGET_ABI TARGET_PRODUCT_ABI TARGET_PYTHON

.PHONY: package clean
package:
	ABI="$(ABI)" VERSION="$(VERSION)" sh ./build.sh

clean:
	rm -rf work/freebsd-pkg
