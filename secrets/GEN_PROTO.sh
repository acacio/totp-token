#!/bin/sh
#protoc --go_out=plugins=grpc,import_path=.:. *.proto
protoc --go_out=plugins=:. *.proto
