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

# replacement for the mininet/util/m in the master branch that works with 2.0.0
# this script assumes that a patched mnexec is found at ~/mininet/mnexec

mnexec="sudo `cd ~; pwd`/mininet/mnexec"

is_debug=false
is_list=false
function debug {
    $is_debug || return
    echo >&2 "$@"
}

if test "$1" = "-d" ; then
    is_debug=true
    shift
fi

if test "$1" = "-l" ; then
    is_list=true
    shift
fi

host=$1
shift

function usage {
    cat >&2 <<EOU
Usage: $0 [-d] [-l | HOST [addr | CMD [ARG...]]]

    -d      print debug messages
    -l      list all hosts
    HOST    mininet host name
    CMD     [ARG...]: the optional command and argument (default is bash)
    addr    the pseudo command 'addr' will print the IP address of HOST
EOU
    exit 1
}

if $is_list ; then
    if test -n "$host" ; then
        echo >&2 $0: cannot specify extra parameters with -l
        usage
    fi
elif test -z "$host" || test "$host" = "-h" ; then
    usage
fi

cmd=$1
shift
if test -z "$cmd" ; then
    cmd=bash
fi

function get_host() {
    $mnexec -a $1 ip link | \
        sed -n -e 's/^[0-9][0-9]*: \('[^-]*'\)-eth0: .*$/\1/p' 
}

function get_addr() {
    $mnexec -a $1 ifconfig $2-eth0 | \
        sed -n -e 's/^[ 	]*inet addr:\([0-9.]*\)[ 	].*$/\1/p'
}

declare -A hosts
names=''
p=
for pid in `ps ax | awk '/[ ]bash -m/{print $1}'` ; do
    h=`get_host $pid`
    if test -n "$h" ; then
        hosts[$h]=`get_addr $pid $h`
        names="$names $h"
        debug $pid $h ${hosts[$h]}
    fi
    test "$h" = "$host" || continue
    p=$pid
done

if test -z "$p" ; then
    echo >&2 $0: cannot find pid for host "'$host'"
    exit 1
fi

if $is_list ; then
    echo $names
    exit 0
fi

if test "$cmd" = "addr" ; then
    echo ${hosts[$host]}
    exit 0
fi

args=()
for arg ; do
    addr="${hosts[$arg]}"
    if test -n "$addr" ; then
        arg="$addr"
    fi
    args[${#args[@]}]="$arg"
done

debug Running: "$cmd" "${args[@]}"
exec $mnexec -a $p "$cmd" "${args[@]}"

