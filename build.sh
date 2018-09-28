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
    python -m pytest --junit-xml test-results.xml tests
    ;;
  package)
    ./bin/create_package.sh
    ;;
  push)
    ./bin/upload_pypi.sh
    ;;
  *)
    echo "Usage: $0 { build | test | package | push }"
    exit 1
esac
