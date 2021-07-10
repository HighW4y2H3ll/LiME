#!/bin/bash

pushd src
KDIR=../../kernel make $@
popd
