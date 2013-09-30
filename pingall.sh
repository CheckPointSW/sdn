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

dir=`dirname $0`
dir=`cd $dir; pwd`
m=$dir/m
hosts=''
for h in `$m -l` ; do
    if expr $h : fw > /dev/null ; then
        continue
    fi
    hosts="$hosts $h"
done
for s in $hosts ; do
    printf '%s:%-15s ->\n' $s `$m $s addr`
    for d in $hosts ; do
        if test $d = $s ; then
            continue
        fi
        printf '\t%s:' $d
        if $m $s ping -c1 -W1 $d >/dev/null ; then
            printf "%-15s " `$m $d addr`
        else
            printf "%-15s " '  X'
        fi
    done
    echo
done
