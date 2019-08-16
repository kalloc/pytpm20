build:
	mkdir -p .build
	cd .build && cmake ../ && make

clean:
	rm -rf .build/src/

tools: build
	.build/src/demo -Tdevice --random

