.PHONY: test test_all lint format

# Set the shell to bash for recipe execution.
SHELL:=/bin/bash

# Rule-function to check if a given command is installed.
define CHECK_COMMAND
.PHONY: check_installed_$(1)
check_installed_$(1):
	@command -v $(1) >/dev/null 2>&1 || (echo "Error: $(1) is not installed or not in PATH. Please install $(1)." >&2; exit 1)
endef
$(foreach cmd,docker yq,$(eval $(call CHECK_COMMAND,$(cmd))))


# Read the environment variables for super-linter from the GitHub Actions
# workflow file to ensure consistency between local and CI linting.
GITHUB_WORKFLOW_FILE := .github/workflows/lint.yml
SUPER_LINTER_ENV_FLAGS := $(shell yq eval \
    ".jobs.super-linter.steps[] | select(.uses | contains(\"super-linter/super-linter\")).env | to_entries | .[] | select(.key != \"GITHUB_TOKEN\") | select(.key != \"VALIDATE_ALL_CODEBASE\") | \"-e \(.key)=\(.value)\"" \
    "$(GITHUB_WORKFLOW_FILE)")

# Define the version of super-linter to use.
SUPER_LINTER_VERSION := "v8.2.0"

# Get the absolute path to the root of the main git repository.
GIT_MAIN := $(shell git rev-parse --path-format=absolute --git-common-dir | sed 's/\/\.git//')

lint: check_installed_docker check_installed_yq
	@[ ! -n "$$(git status --porcelain)" ] || \
		( \
			echo "Error: There are uncommitted changes. Please commit or stash them before running superlint."; \
			exit 1; \
		)
	@docker run \
		--platform linux/amd64 \
		$(SUPER_LINTER_ENV_FLAGS) \
		-e DEFAULT_BRANCH=main \
		-e LOG_LEVEL=NOTICE \
		-e RUN_LOCAL=true \
		-e VALIDATE_ALL_CODEBASE=false \
		-v "$(shell pwd):/tmp/lint" \
		-v "$(GIT_MAIN):$(GIT_MAIN)" \
		ghcr.io/super-linter/super-linter:$(SUPER_LINTER_VERSION)

FORMATTERS := \
	CLANG_FORMAT \
	GITHUB_ACTIONS_ZIZMOR \
	JSON_PRETTIER \
	MARKDOWN \
	MARKDOWN_PRETTIER \
	NATURAL_LANGUAGE \
	PYTHON_BLACK \
	PYTHON_RUFF \
	TYPESCRIPT_PRETTIER \
	YAML_PRETTIER
FORMAT_FLAGS := $(foreach arg, $(FORMATTERS), -e FIX_$(arg)=true)

format: check_installed_docker check_installed_yq
	@[ ! -n "$$(git status --porcelain)" ] || \
		( \
			echo "Error: There are uncommitted changes. Please commit or stash them before running superlint."; \
			exit 1; \
		)
	@docker run \
		--platform linux/amd64 \
		$(SUPER_LINTER_ENV_FLAGS) \
		$(FORMAT_FLAGS) \
		-e DEFAULT_BRANCH=main \
		-e LOG_LEVEL=NOTICE \
		-e RUN_LOCAL=true \
		-e VALIDATE_ALL_CODEBASE=false \
		-v "$(shell pwd):/tmp/lint" \
		-v "$(GIT_MAIN):$(GIT_MAIN)" \
		ghcr.io/super-linter/super-linter:$(SUPER_LINTER_VERSION)

fix_license:
	@docker run --rm --volume $(shell pwd):/data --workdir /data \
		--entrypoint /bin/sh \
		fsfe/reuse -c '\
		find . -type f \( -name "*.py" -o -name "*.yaml" -o -name "*.yml" \) \
		! -path "./venv/*" ! -path "./.venv/*" ! -path "./.*/*" \
		-exec reuse annotate \
		--copyright-prefix string \
		--copyright "Cisco Systems, Inc. and its affiliates" \
		-l "Apache-2.0" {} +'
