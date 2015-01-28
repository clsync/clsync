#!/bin/bash

#
# author: Enrique Martinez <enmaca@hotmail.com>
# license: GPL-3+
#

GITREV=$(git rev-parse --short HEAD)
VERSION=${GITREV}git

inc_version() {
local v=$1
if [ -z $2 ]; then
local tdk='^((?:[0-9]+\.)*)([0-9]+)($)'
else
local tdk='^((?:[0-9]+\.){'$(($2-1))'})([0-9]+)(\.|$)'
for (( p=`grep -o "\."<<<".$v"|wc -l`; p<$2; p++)); do v+=.0; done;
fi
val=`echo -e "$v" | perl -pe 's/^.*'$tdk'.*$/$2/'`
echo "$v" | perl -pe s/$tdk.*$'/${1}'`printf %0${#val}s $(($val+1))`/
}

GITROOT=$(git rev-parse --show-toplevel)
cd $GITROOT

if [ -f $GITROOT/rpm/$VERSION.buildnum ]; then
BUILDNUM=`cat ./rpm/$VERSION.buildnum`
else
BUILDNUM=0
fi

BUILDNUM=$(inc_version $BUILDNUM)
echo $BUILDNUM > $GITROOT/rpm/$VERSION.buildnum

RPMTOPDIR=$GITROOT/rpm/build

if [ ! -d $RPMTOPDIR ]; then
mkdir -p $RPMTOPDIR
fi


echo "BUILDING RPM Version: $VERSION, BuildNumber: $BUILDNUM"

mkdir -p $RPMTOPDIR/{SOURCES,SPECS}
git archive --format=tar --prefix=clsync-${VERSION}/ HEAD | gzip -c > $RPMTOPDIR/SOURCES/clsync-${VERSION}.tar.gz
sed -e "s/@VERSION@/$VERSION/" -e "s/@BUILDNUM@/$BUILDNUM/" $GITROOT/rpm/clsync.spec > $RPMTOPDIR/SPECS/clsync.spec
cat $GITROOT/rpm/clsync.init > $RPMTOPDIR/SOURCES/clsync.init

rpmbuild    --quiet                       \
--define "_topdir $RPMTOPDIR" \
--define "_rpmdir $GITROOT/rpm"       \
--define "_srcrpmdir $GITROOT/rpm"    \
--define '_rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm' \
-ba $RPMTOPDIR/SPECS/clsync.spec &&

rm -rf $RPMTOPDIR &&
echo Done