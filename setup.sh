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

echo >&2 Install mininet \(including pox\)...
cd $HOME
git clone  https://github.com/mininet/mininet
cd mininet
git checkout 2.0.0
cd $HOME
./mininet/util/install.sh -fnpv

echo >&2 Patch mininet mnexec to allow our ./m script to work...
cd $HOME/mininet
sed -i 's/syscall(308/syscall(__NR_setns/' mnexec.c
make mnexec

echo >&2 Customize pox to use our code...
ln -s ~/sdn/fw.py ~/pox/ext/fw.py
ln -s ~/sdn/heapdict.py ~/pox/ext/heapdict.py

echo >&2 Install tcpreplay...
sudo apt-get -y install tcpreplay

echo >&2 Install socat...
sudo apt-get -y install socat

