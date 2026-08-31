#!/bin/bash
set -e

echo "=== Running h2tunnel Unit & E2E Tests ==="
go test -v -race ./...
echo "=== All Tests Passed! ==="
