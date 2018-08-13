#! /bin/sh
SCRIPT_DIR=`dirname $0`
twine upload ${SCRIPT_DIR}/../dist/ubirch-protocol-*.tar.gz
