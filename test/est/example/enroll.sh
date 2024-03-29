#!/usr/bin/env bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR/../../../
BCDIR=`pwd`
popd

$DIR/ensurejar.sh

CP="$DIR/jars/util.jar:$DIR/jars/pkix.jar:$DIR/jars/bcprov.jar:$DIR/jars/test.jar:$DIR/jars/bctls.jar"
echo $CP
java -classpath $CP com.distrimind.bouncycastle.test.est.examples.EnrollExample --sl $DIR/jars/suffixlist.dat $@
