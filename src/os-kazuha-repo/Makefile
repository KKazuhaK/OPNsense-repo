VERSION?= 1.0.0
TARGET_PRODUCT_ABI?= 26.7

.PHONY: package clean
package:
	VERSION="$(VERSION)" TARGET_PRODUCT_ABI="$(TARGET_PRODUCT_ABI)" sh ./build.sh

clean:
	rm -rf work/freebsd-pkg
