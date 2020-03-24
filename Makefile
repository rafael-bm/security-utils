SHELL := /bin/bash

clean:
	./gradlew clean

compile: clean
	./gradlew build

