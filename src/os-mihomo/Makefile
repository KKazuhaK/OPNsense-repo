VERSION?= 1.2.0

.PHONY: package clean
package:
	TARGET_PROFILE="$(TARGET_PROFILE)" TARGET_ABI="$(TARGET_ABI)" \
	    TARGET_PRODUCT_ABI="$(TARGET_PRODUCT_ABI)" TARGET_PYTHON="$(TARGET_PYTHON)" \
	    ABI="$(ABI)" VERSION="$(VERSION)" sh ./build.sh

clean:
	rm -rf work/freebsd-pkg
