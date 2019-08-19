.PHONY: dist build

build:
	mkdir -p .build
	cd .build && cmake ../ && make

clean:
	rm -rf .build/src/

python:
	python setup.py build -b .build

test: build python
	.build/src/demo -Tdevice --random

export:
	mkdir -p dist/
	tar zcf dist/tpm20.src.tar.gz $(shell git ls-files)
