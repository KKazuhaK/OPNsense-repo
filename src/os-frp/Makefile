PKG_NAME?=	os-frp
VERSION?=	1.0.0
PYTHON?=	python3.13

.PHONY: package pin-checksum test clean
package:
	PKG_NAME="$(PKG_NAME)" VERSION="$(VERSION)" sh ./build.sh

# One-time pin of the vendored upstream archive, after its digest has been
# checked against the checksum published with the frp release.
pin-checksum:
	FRP_PIN_CHECKSUM=1 sh ./build.sh

test:
	$(PYTHON) -B -m unittest discover -s tests -v

clean:
	rm -rf work dist
