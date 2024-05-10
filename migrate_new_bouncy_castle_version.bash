#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <BCVersion>"
    exit 1
fi

BCVersion=$1
projectVersion=""
while read CMD; do
  if [ -n "$CMD" ]; then
    if [ -n "$projectVersion" ]; then
      projectVersion="$projectVersion.$CMD"
    else
      projectVersion="$CMD"
    fi
  fi
done  < <(echo "$BCVersion" | grep -o -E '[0-9]+')

cd ../bc-test-data || exit

git pull

cd ../bc-java || exit

git pull || exit

git reset --hard "$BCVersion" || exit

cd ../BouncyCastle || exit
sed -i "s/^\tversion = '.*'/\tversion = '$projectVersion'/" build.gradle

#migrate core files
rm -rf core/src/main/java/com/distrimind/bouncycastle
rm -rf core/src/main/resources/com/distrimind/bouncycastle

rm -rf core/src/test/java/com/distrimind/bouncycastle
rm -rf core/src/test/resources/com/distrimind/bouncycastle


cp -r ../bc-java/core/src/main/java/org/bouncycastle core/src/main/java/com/distrimind
cp -r ../bc-java/core/src/main/resources/org/bouncycastle core/src/main/resources/com/distrimind

cp -r ../bc-java/core/src/test/java/org/bouncycastle core/src/test/java/com/distrimind
cp -r ../bc-java/core/src/test/resources/org/bouncycastle core/src/test/resources/com/distrimind

#migrate prov files

rm -rf prov/src/main/java/com/distrimind/bouncycastle
rm -rf prov/src/main/resources/com/distrimind/bouncycastle

rm -rf prov/src/test/java/com/distrimind/bouncycastle
rm -rf prov/src/test/resources/com/distrimind/bouncycastle


cp -r ../bc-java/prov/src/main/java/org/bouncycastle prov/src/main/java/com/distrimind
cp -r ../bc-java/prov/src/main/resources/org/bouncycastle prov/src/main/resources/com/distrimind
cp -r ../bc-java/prov/src/main/resources/META-INF prov/src/main/resources/

cp -r ../bc-java/prov/src/test/java/org/bouncycastle prov/src/test/java/com/distrimind
cp -r ../bc-java/prov/src/test/resources/org/bouncycastle prov/src/test/resources/com/distrimind
cp -r ../bc-java/prov/src/test/resources/PKITS prov/src/test/resources

rm -r prov/src/test/java/com/distrimind/bouncycastle/test/JVMVersionTest.java

#migrate util files

rm -rf util/src/main/java/com/distrimind/bouncycastle

rm -rf util/src/test/java/com/distrimind/bouncycastle
rm -rf util/src/test/resources/com/distrimind/bouncycastle

cp -r ../bc-java/util/src/main/java/org/bouncycastle util/src/main/java/com/distrimind

cp -r ../bc-java/util/src/test/java/org/bouncycastle util/src/test/java/com/distrimind
cp -r ../bc-java/util/src/test/resources/org/bouncycastle util/src/test/resources/com/distrimind

find . \( -path "./.git" -o -path "./.gradle" -o -name "migrate_new_bouncy_castle_version.bash" \) -prune -o -type f -exec sed -i 's/org\.bouncycastle/com\.distrimind\.bouncycastle/g' {} +
find . \( -path "./.git" -o -path "./.gradle" -o -name "migrate_new_bouncy_castle_version.bash" \) -prune -o -type f -exec sed -i 's/org\/bouncycastle/com\/distrimind\/bouncycastle/g' {} +
find . \( -path "./.git" -o -path "./.gradle" -o -name "migrate_new_bouncy_castle_version.bash" \) -prune -o -type f -exec sed -i 's/org\.bouncycastle/com\.distrimind\.bouncycastle/g' {} +

echo "Migration réussie."
