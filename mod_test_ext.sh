#!/bin/sh

if ! [ -x "$(command -v openjdk_11)" ]; then
    JAVA_11=/usr/lib/jvm/java-11-openjdk-amd64
  else
    JAVA_11=`openjdk_11`
fi


export JAVA_HOME=$JAVA_11

artifactsHome=build/artifacts/jdk1.8/jars

tj=( $artifactsHome/bctest-jdk18on-*.jar )

testJar="${tj[0]}";

rm -rf mtest
mkdir mtest

cp $artifactsHome/*.jar mtest/

rm mtest/bcjmail-*
rm mtest/bcprov-*
rm mtest/bctest-*

cp $artifactsHome/bcprov-ext-* mtest/


for j in mtest/*.jar; do
jar -tf $j | grep module-info\.class >> /dev/null

if [[ $? != 0 ]]; then
    echo "$j is missing module-info"
    exit 1;
else
     echo "$j is has module-info"
fi

done


a=(`$JAVA_HOME/bin/jar -tf "$testJar" | grep -E "AllTests\.class" | sed -e 's!.class!!' | sed -e 's|/|.|g'`);

echo $testJar

for i in "${a[@]}"
do
  echo $i

#  case $i in org\.bouncycastle\.pqc\.legacy\.*)
#   echo "skipping $i"
#   continue
#  esac


   $JAVA_HOME/bin/java --module-path ./mtest/ \
   --add-modules com.distrimind.bouncycastle.mail \
   --add-modules com.distrimind.bouncycastle.pg \
   --add-modules com.distrimind.bouncycastle.pkix \
   --add-modules com.distrimind.bouncycastle.provider \
   --add-modules com.distrimind.bouncycastle.tls \
   --add-modules com.distrimind.bouncycastle.util \
   --add-opens com.distrimind.bouncycastle.provider/com.distrimind.bouncycastle.jcajce.provider.symmetric=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.provider/com.distrimind.bouncycastle.jcajce.provider.digest=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.asn1.cmc=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.oer.its.etsi102941.basetypes=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.oer.its.etsi102941=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.oer.its.ieee1609dot2dot1=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.oer.its.etsi103097.extension=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.oer.its.etsi103097=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.oer.its.ieee1609dot2.basetypes=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.util/com.distrimind.bouncycastle.oer.its.ieee1609dot2=ALL-UNNAMED \
   --add-opens com.distrimind.bouncycastle.pkix/com.distrimind.bouncycastle.tsp=ALL-UNNAMED \
   --add-reads com.distrimind.bouncycastle.mail=ALL-UNNAMED \
   --add-reads com.distrimind.bouncycastle.provider=ALL-UNNAMED \
   --add-exports com.distrimind.bouncycastle.provider/com.distrimind.bouncycastle.internal.asn1.cms=ALL-UNNAMED \
   --add-exports com.distrimind.bouncycastle.provider/com.distrimind.bouncycastle.internal.asn1.bsi=ALL-UNNAMED \
   --add-exports com.distrimind.bouncycastle.provider/com.distrimind.bouncycastle.internal.asn1.eac=ALL-UNNAMED \
   -cp "$testJar:libs/junit-4.13.2.jar:libs/javax.mail-1.4.7.jar:libs/activation-1.1.1.jar" \
   -Dbc.test.data.home=core/src/test/data \
    $i

    if [[ $? != 0 ]]; then
        echo ""
        echo "--------------------------------!!!"
        echo "$i failed"
        exit 1;
    fi

    echo "-------------------------------------"
    echo ""
done


