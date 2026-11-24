#!/bin/sh
# 每個 fuzz 目標各跑一段時間（預設 1h）：scripts/fuzz.sh [時間，例如 15m]
set -e
t=${1:-1h}
go test -run='^$' -fuzz='^FuzzDecode$'             -fuzztime="$t" ./uacp
go test -run='^$' -fuzz='^FuzzMessageChunkDecode$' -fuzztime="$t" ./uasc
go test -run='^$' -fuzz='^FuzzVerifyAndDecrypt$'   -fuzztime="$t" ./uasc
go test -run='^$' -fuzz='^FuzzDecodeService$'      -fuzztime="$t" ./ua
go test -run='^$' -fuzz='^FuzzEventFilter$'        -fuzztime="$t" ./server
