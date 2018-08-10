#! /bin/sh
SCRIPT_DIR=`dirname $0`
(cd ${SCRIPT_DIR}/..;
  python3 -m unittest discover &&
  python3 setup.py sdist bdist_wheel
)