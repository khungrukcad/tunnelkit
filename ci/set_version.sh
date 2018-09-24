#!/bin/sh
PWD=`dirname $0`
VERSION=`cat $PWD/VERSION`
BUILD=`git rev-list HEAD --count`
agvtool new-marketing-version $VERSION
agvtool new-version $BUILD

echo "Setting podspec version to $VERSION..."
sed -i "" -E 's@s\.version( +)= "[0-9]+\.[0-9]+\.[0-9]+"$@s.version\1= "'$VERSION'"@g' TunnelKit.podspec
