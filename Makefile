UV_FLAGS ?= --inexact --no-group prod --group dev --all-extras $(UV_FLAGS_EXTRA)
UV_RUN ?= env VIRTUAL_ENV=.venv uv run $(UV_FLAGS)


TEST_FLAGS ?=

all: format lint mypy test

fix: format-fix lint-fix

format:
	@$(UV_RUN) --group format ruff format --check

format-fix:
	@$(UV_RUN) --group format ruff format

lint:
	@$(UV_RUN) --group lint ruff check

lint-fix:
	@$(UV_RUN) --group lint ruff check --fix

mypy:
	@$(UV_RUN) --group typing mypy src/enochecker3/

build:
	@uv build

test:
	@test -z "$(shell ls tests)" || \
		($(UV_RUN) --group test coverage run -m pytest -W error -v $(TEST_FLAGS) && \
		$(UV_RUN) --group test coverage report -m)

sync:
	@uv sync $(UV_FLAGS)

dev:
	@git update-index --assume-unchanged lib/enochecker-core/pyproject.toml
	@rm -rf lib/enochecker-core
	@git clone git@github.com:attacking-lab/enochecker-core lib/enochecker-core

.PHONY: all fix format format-fix lint lint-fix mypy test build sync dev
