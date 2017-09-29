#!/bin/sh
#protoc --go_out=plugins=grpc,import_path=.:. *.proto
protoc --go_out=. -osecrets.desc *.proto
protoc --js_out=. *.proto
