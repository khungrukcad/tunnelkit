#!/bin/sh
VERSION="1.1.0"
BUILD=`git rev-list HEAD --count`

agvtool new-marketing-version $VERSION
agvtool new-version $BUILD
