#!/usr/bin/env bash

CIDIR=$(dirname $(readlink -fn $0))
UNINSTALL=0
UNINSTALL_ALL=0
source $CIDIR/ci.functions

MAKE=`which make`

if [ x"$DESTDIR" != x ] ; then
	mkdir -p "$DESTDIR"
fi

if [[ "$BRANCH_NAME" =~ devel(opment)?/([0-9]+)/.+ ]] ; then
	export MAINLINE_BRANCH="${BASH_REMATCH[2]}"
fi
_version=$(./build_tools/make_version .)

destdir=${DESTDIR:+DESTDIR=$DESTDIR}

declare -p _version
declare -p destdir

[ $UNINSTALL -gt 0 ] && ${MAKE} ${destdir} uninstall
[ $UNINSTALL_ALL -gt 0 ] && ${MAKE} ${destdir} uninstall-all

${MAKE} ${destdir} install || ${MAKE} ${destdir} NOISY_BUILD=yes install || exit 1
${MAKE} ${destdir} samples install-headers
if [ x"$DESTDIR" != x ] ; then
	sed -i -r -e "s@\[directories\]\(!\)@[directories]@g" $DESTDIR/etc/gabpbx/gabpbx.conf
	sed -i -r -e "s@ /(var|etc|usr)/@ $DESTDIR/\1/@g" $DESTDIR/etc/gabpbx/gabpbx.conf
fi

set +e
if [ x"$USER_GROUP" != x ] ; then
	chown -R $USER_GROUP $DESTDIR/var/cache/gabpbx
	chown -R $USER_GROUP $DESTDIR/var/lib/gabpbx
	chown -R $USER_GROUP $DESTDIR/var/spool/gabpbx
	chown -R $USER_GROUP $DESTDIR/var/log/gabpbx
	chown -R $USER_GROUP $DESTDIR/var/run/gabpbx
	chown -R $USER_GROUP $DESTDIR/etc/gabpbx
fi
ldconfig
