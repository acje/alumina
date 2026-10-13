#!/bin/sh
echo "$$" > "/w/${STAMP}.candidate.pid"
exec /usr/local/bin/envoy -c /cfg/envoy_connect.yaml --concurrency 1
