#!/usr/bin/env bash

set -ex
npm run docker:compose-test-up
npm run build:clean
npm run build
npm run build:test

((npm run jasmine && npm run say:pass) || (npm run say:fail ; exit 1))
