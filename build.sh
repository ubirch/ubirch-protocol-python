#!/usr/bin/env bash

python3 -m venv venv
. ./venv/bin/activate
pip --no-cache-dir install -r requirements.txt
PYTHONPATH=.

case $1 in
  build)
     python -m compileall ubirch tests examples
    ;;
  test)
    pip --no-cache-dir install -r requirements.test.txt
    python -m pytest --junit-xml test-report.xml tests
    python -c 'import xml.dom.minidom; print(xml.dom.minidom.parse("test-report.xml").toprettyxml())' > /tmp/report.xml
    mv /tmp/report.xml test-report.xml
    ;;
  package)
    pip --no-cache-dir install wheel
    ./bin/create_package.sh
    ;;
  push)
    VERSION=$(python setup.py --version)
    git tag -a "v$VERSION+$2" -m "release v$VERSION+$2"
    git describe
    ./bin/upload_pypi.sh
    ;;
  *)
    echo "Usage: $0 { build | test | package | push }"
    exit 1
esac
