#!/usr/bin/env bash
CIDIR=$(dirname $(readlink -fn $0))
CLEANUP_DB=0
source $CIDIR/ci.functions

cp test-config.orig.yaml test-config.yaml
if [ $CLEANUP_DB -gt 0 ] ; then
	sudo -u postgres dropdb -e gabpbx_test >/dev/null 2>&1 || :
	sudo -u postgres dropuser -e gabpbx_test  >/dev/null 2>&1 || :
	sudo odbcinst -u -d -n "PostgreSQL-GABpbx-Test"
	sudo odbcinst -u -s -l -n "gabpbx-connector-test"
fi
