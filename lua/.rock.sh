#!/usr/bin/env bash

package="aes_everywhere"
tag=$(git tag | tail -1 | sed -e 's/^v//')

i=0
while true; do
  rev="$tag-$i"
  specfile="$package-$rev.rockspec"
  if [[ ! -f "$specfile" ]]; then
    break
  fi
  i=$((i+1))
done

cat package-template.rockspec > "$specfile"
sed -i 's/\$VERSION\$/'"$rev"'/g' "$specfile"
sed -i 's/\$PACKAGE\$/'"$package"'/g' "$specfile"

luarocks pack "$specfile"
