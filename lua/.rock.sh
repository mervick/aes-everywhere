#!/usr/bin/env bash

#if [[ `git status --porcelain` ]]; then
#  (1>&2 echo 'You have uncommitted changes. Please commit it first')
#  exit 1
#fi

git checkout master -f

package="aes_everywhere"

tag=$(git tag | tail -1 | sed -e 's/^v//')
rev="$tag-0"
package_tag="$package-$rev"
specfile="$package_tag.rockspec"
tmpdir="$(mktemp -d)"
mkdir "$tmpdir"

rsync -a lua/src/ "$tmpdir/src/"
cat aes_everywhere-scm-0.rockspec > "$tmpdir/$specfile"
sed -i 's/"scm-0"/"'"$rev"'"/g' "$tmpdir/$specfile"

luarocks pack 

cp README.md  "$tmpdir/"
cp ../LICENSE "$tmpdir/"

git checkout --orphan lua-package
code=$?
if [[ $code == 128 ]]; then
  git checkout lua-package
fi

git rm -rf .

rsync -a "$tmpdir/" .

for f in "$tmpdir"/*; do 
  git add "${f##*/}"
done

git commit -m "Create lua package $tag"
git tag "$tag"

#rm ${tarfile}
#tar -cvf ${tarfile} src/
#tar rvf  ${tarfile} README.md
#tar rvf  ${tarfile} ../LICENSE
#
#
#https://raw.githubusercontent.com/mervick/machining-website/master/public/assets/files/14313203.mp4?token=AASRC4XJEWVQB6U4CQ42YLS6IIBBM
#https://github.com/mervick/machining-website/blob/master/public/assets/files/14313203.mp4
#
#blob/0.1.0

#cp ../LICENSE ./
#
#tar czvpf 