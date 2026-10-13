#!/bin/sh
echo "$$" > "/w/${STAMP}.candidate.pid"
exec /usr/local/sbin/haproxy -db -f /cfg/haproxy.cfg
