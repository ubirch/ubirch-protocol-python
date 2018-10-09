#!/usr/bin/env bash

python3 -m venv venv
. ./venv/bin/activate

case $1 in
  build)
    pip --no-cache-dir install -r requirements.txt
    PYTHONPATH=. python -m compileall ubirch tests examples
    ;;
  test)
    pip --no-cache-dir install -r requirements.test.txt
    python -m pytest --junit-xml test-report.xml tests
    python -c 'import xml.dom.minidom; print(xml.dom.minidom.parse("test-report.xml").toprettyxml())' > /tmp/report.xml
    mv /tmp/report.xml test-report.xml
    ;;
  package)
    VERSION=$(python setup.py --version)
    TAGGED=$(git describe --exact-match HEAD)
    if [ "v$VERSION" eq "$TAGGED" ]; then
      pip --no-cache-dir install wheel
      ./bin/create_package.sh
    else
      echo "not a tagged version, not packaging"
      exit -1
    fi
    ;;
  push)
    VERSION=$(python setup.py --version)
    TAGGED=$(git describe --exact-match HEAD)
    if [ "v$VERSION" eq "$TAGGED" ]; then
      pip --no-cache-dir install twine
      twine upload dist/*
    else
      echo "Version does not match tag: '$VERSION' != '$TAGGED', not pushed!"
      exit -1
    fi
    ;;
  *)
    echo "Usage: $0 { build | test | package | push }"
    exit 1
esac
