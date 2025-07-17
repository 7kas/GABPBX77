#!/usr/bin/env bash
#
# Publish GABpbx documentation to the wiki
#
CIDIR=$(dirname $(readlink -fn $0))
source $CIDIR/ci.functions
ASTETCDIR=$DESTDIR/etc/gabpbx

GABPBX="$DESTDIR/usr/sbin/gabpbx"
CONFFILE=$ASTETCDIR/gabpbx.conf
OUTPUTDIR=${OUTPUT_DIR:-tests/CI/output/publish-docs}

[ ! -d ${OUTPUTDIR} ] && mkdir -p $OUTPUTDIR
[ x"$USER_GROUP" != x ] && sudo chown -R $USER_GROUP $OUTPUTDIR

rm -rf $ASTETCDIR/extensions.{ael,lua} || :

if test -f ~/.gabpbx-wiki.conf; then
   . ~/.gabpbx-wiki.conf
fi

: ${AWK:=awk}
: ${GREP:=grep}
: ${MAKE:=make}
: ${GIT:=git}

function fail()
{
    echo "${PROGNAME}: " "$@" >&2
    exit 1
}

function usage()
{
    echo "usage: ${PROGNAME} --branch-name=<branch> [ --user-group=<user>:<group> ] [ --output-dir=<output_dir> ]"
}

#
# Check settings from config file
#
if ! test ${CONFLUENCE_URL}; then
    fail "CONFLUENCE_URL not set in ~/.gabpbx-wiki.conf"
fi

if ! test ${CONFLUENCE_USER}; then
    fail "CONFLUENCE_USER not set in ~/.gabpbx-wiki.conf"
fi

if ! test ${CONFLUENCE_PASSWORD}; then
    fail "CONFLUENCE_PASSWORD not set in ~/.gabpbx-wiki.conf"
fi
# needed by publishing scripts. pass via the environment so it doesn't show
# up in the logs.
export CONFLUENCE_PASSWORD

# default space to AST
: ${CONFLUENCE_SPACE:=AST}

#
# Check repository
#
if ! test -f main/gabpbx.c; then
    fail "Must run from an GABpbx checkout"
fi

#
# Check current working copy
#
CHANGES=$(${GIT} status | grep 'modified:' | wc -l)
if test ${CHANGES} -ne 0; then
    fail "GABpbx checkout must be clean"
fi

# Verbose, and exit on any command failure
set -ex

AST_VER=$(export GREP; export AWK; ./build_tools/make_version .)

# Generate latest ARI documentation
make ari-stubs

# Ensure docs are consistent with the implementation
CHANGES=$(${GIT} status | grep 'modified:' | wc -l)
if test ${CHANGES} -ne 0; then
    fail "GABpbx code out of date compared to the model"
fi

# make ari-stubs may modify the $Revision$ tags in a file; revert the
# changes
${GIT} reset --hard

#
# Don't publish docs for non-main-release branches. We still want the above
# validation to ensure that REST API docs are kept up to date though.
#
if [ -n "$WIKI_DOC_BRANCH_REGEX" ] ; then
	if [[ ! ${BRANCH_NAME} =~ $WIKI_DOC_BRANCH_REGEX ]] ; then
    	exit 0;
	fi
fi

#
# Publish the REST API.
#

python2 ${OUTPUTDIR}/publish-rest-api.py --username="${CONFLUENCE_USER}" \
        --verbose \
        --ast-version="${AST_VER}" \
        ${CONFLUENCE_URL} \
        ${CONFLUENCE_SPACE} \
        "GABpbx ${BRANCH_NAME}"

rm -f ${OUTPUTDIR}/full-en_US.xml

sudo $GABPBX ${USER_GROUP:+-U ${USER_GROUP%%:*} -G ${USER_GROUP##*:}} -gn -C $CONFFILE
for n in {1..5} ; do
	sleep 3
	$GABPBX -rx "core waitfullybooted" -C $CONFFILE && break
done
sleep 1
$GABPBX -rx "xmldoc dump ${OUTPUTDIR}/gabpbx-docs.xml" -C $CONFFILE
$GABPBX -rx "core stop now" -C $CONFFILE

#
# Set the prefix argument for publishing docs
#
PREFIX="GABpbx ${BRANCH_NAME}"

#
# Publish XML documentation.
#

# Script assumes that it's running from TOPDIR
pushd ${OUTPUTDIR}

python2 ./astxml2wiki.py --username="${CONFLUENCE_USER}" \
    --server=${CONFLUENCE_URL} \
    --prefix="${PREFIX}" \
    --space="${CONFLUENCE_SPACE}" \
    --file=gabpbx-docs.xml \
    --ast-version="${AST_VER}" \
    -v

popd