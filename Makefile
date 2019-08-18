build:
	mkdir -p .build
	cd .build && cmake ../ && make

clean:
	rm -rf .build/src/

python:
	python setup.py build -b .build

test: build python
	.build/src/demo -Tdevice --random
