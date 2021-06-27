.PHONY: all lint diff format test

all: format test

lint:
	python3 -m isort -c enochecker3/ tests/
	python3 -m black --check enochecker3/ tests/
	python3 -m flake8 enochecker3/  tests/
	python3 -m mypy enochecker3/ tests/

diff:
	python3 -m isort --diff enochecker3/ tests/
	python3 -m black --diff enochecker3/ tests/

format:
	python3 -m isort enochecker3/ tests/
	python3 -m black enochecker3/ tests/

test:
	pip3 install .
ifdef GITHUB_ACTIONS
	coverage run -m pytest -v --with_mongodb
else
	coverage run -m pytest -v
endif
	coverage report -m
