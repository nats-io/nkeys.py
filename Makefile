REPO_OWNER=nats-io
PROJECT_NAME=nkeys.py
SOURCE_CODE=src/nkeys


help:
	@cat $(MAKEFILE_LIST) | \
	grep -E '^[a-zA-Z_-]+:.*?##' | \
	sed "s/local-//" | \
	sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


clean:
	find . -name "*.py[co]" -delete


deps:
	uv sync --extra dev


format:
	uv run yapf -i --recursive $(SOURCE_CODE)
	uv run yapf -i --recursive tests


test:
	uv run yapf --recursive --diff $(SOURCE_CODE)
	uv run yapf --recursive --diff tests
	uv run mypy
	uv run flake8 ./$(SOURCE_CODE)/
	uv run pytest


ci: deps
	uv run flake8 --ignore=W391 ./$(SOURCE_CODE)/
	uv run pytest -x -vv -s --continue-on-collection-errors

watch:
	while true; do uv run pytest -v -s -x; sleep 10; done
