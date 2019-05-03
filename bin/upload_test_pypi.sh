#! /bin/sh
SCRIPT_DIR=`dirname $0`
twine upload --repository-url https://test.pypi.org/legacy/ ${SCRIPT_DIR}/../dist/*
