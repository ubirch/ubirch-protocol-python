#!/usr/bin/env bash

python3 -m venv venv
. ./venv/bin/activate

case $1 in
  build)
    pip --no-cache-dir install -r requirements.txt
    PYTHONPATH=. python -m compileall ubirch tests examples
    ;;
  test)
    pip --no-cache-dir install -r requirements.txt
    pip --no-cache-dir install -r requirements.test.txt
    python -m pytest --junit-xml test-report.xml tests
    python -c 'import xml.dom.minidom; print(xml.dom.minidom.parse("test-report.xml").toprettyxml())' > /tmp/report.xml
    mv /tmp/report.xml test-report.xml
    ;;
  package)
    VERSION=v$(python setup.py --version 2>/dev/null)
    TAGGED=$(git describe --exact-match HEAD 2>&1)
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
    # check that we are on the master branch where we do releases
    if [ "$BRANCH" != "master" ]; then
      (>&2 echo "ERROR: not master branch ($BRANCH), aborted.")
      exit -1
    fi
    if [ "$VERSION" == "$TAGGED" ]; then
      pip --no-cache-dir install wheel
      ./bin/create_package.sh
    else
      (>&2 echo "ERROR: version does not match tag: '$VERSION' != '$TAGGED', aborted.")
      exit -1
    fi
    ;;
  push)
    VERSION=v$(python setup.py --version 2>/dev/null)
    TAGGED=$(git describe --exact-match HEAD 2>&1)
    BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
    # check that we are on the master branch where we do releases
    if [ "$BRANCH" != "master" ]; then
      (>&2 echo "ERROR: not master branch ($BRANCH), aborted")
      exit -1
    fi
    if [ "$VERSION" == "$TAGGED" ]; then
      pip --no-cache-dir install twine
      twine upload dist/*
    else
      (>&2 echo "ERROR: version does not match tag: '$VERSION' != '$TAGGED', aborted.")
      exit -1
    fi
    ;;
  *)
    echo "Usage: $0 { build | test | package | push }"
    exit 1
esac
