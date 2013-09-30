#!/bin/bash

#   Copyright 2013 Check Point Software Technologies LTD
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

set -x
dir=`dirname $0`
dir=`cd $dir; pwd`
bridge=bridge.py
fw=$1
test -n "$fw" || {
    echo "Usage: $0 GATEWAY-ADDR"
    exit 1
}
port=31173
scp $bridge admin@$fw:
sleep 3 && exec $dir/$bridge replay $fw:$port </dev/null &
pid=$!
trapped=false
function cleanup {
    if $trapped ; then
        return
    fi
    trapped=true
    echo "cleanup for $$"
    kill $pid
    sleep 1
}
trap cleanup 0 HUP INT QUIT PIPE TERM
ssh admin@$fw ./$bridge tap $port
