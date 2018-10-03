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
    pip --no-cache-dir install wheel
    ./bin/create_package.sh
    ;;
  push)
    pip --no-cache-dir install twine
    VERSION=$(python setup.py --version)
    git tag -a "v$VERSION+$2" -m "release v$VERSION+$2"
    git push --tags
    twine upload dist/*
    ;;
  *)
    echo "Usage: $0 { build | test | package | push }"
    exit 1
esac
