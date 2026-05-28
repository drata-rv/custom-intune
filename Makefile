# Builds a Lambda-compatible deployment zip from a Mac (or any non-Linux machine).
#
# The problem: pydantic-core is a compiled Rust extension. Installing it on macOS
# produces a macOS binary that Lambda (Amazon Linux x86_64) cannot load. The
# --platform flag tells pip to fetch the Linux binary instead, without compiling.
#
# Usage:
#   make build                  # Python 3.12, x86_64 (default)
#   make build PYTHON=3.11      # target a different Lambda runtime
#   make build ARCH=arm64       # target arm64 Lambda (Graviton)
#   make clean                  # remove build artifacts

PYTHON     ?= 3.12
ARCH       ?= x86_64
BUILD_DIR  := .build
ZIP_NAME   := custom-intune-lambda.zip
PLATFORM   := manylinux2014_$(ARCH)

.PHONY: build clean

build: clean
	@echo "→ Installing dependencies ($(PLATFORM), Python $(PYTHON))..."
	pip3 install -r requirements.txt \
		--target $(BUILD_DIR) \
		--platform $(PLATFORM) \
		--implementation cp \
		--python-version $(PYTHON) \
		--only-binary=:all: \
		--quiet
	@echo "→ Copying source files..."
	cp -r run.py clients core models pipeline $(BUILD_DIR)/
	@echo "→ Zipping..."
	cd $(BUILD_DIR) && zip -r ../$(ZIP_NAME) . -x "*.pyc" -x "*/__pycache__/*" -q
	@echo "✓ $(ZIP_NAME) is ready to upload to Lambda."

clean:
	rm -rf $(BUILD_DIR) $(ZIP_NAME)
