# Makefile for managing frontend and backend

# Variables
GO_CMD=go
BIN_NAME=kenv
SSH_USER=$(SSH_STAGING_USER)
SSH_HOST=$(SSH_STAGING_HOST)
REMOTE_PATH=~/  # 远程服务器上的目标路径
ENV_FILE=set_env.sh

# Default target
.PHONY: all
all: build upload

# Build backend
.PHONY: build
build:
	@echo "Building ..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO_CMD) build -o ./output/$(BIN_NAME) ./app_manager.go
	@echo "Copying kenv.conf.yml to output directory..."
	mkdir -p output
	cp ./kenv.conf.yml ./output/ # Copy kenv.conf.yml to output directory

# Upload binary to remote server
.PHONY: upload
upload: build
	@echo "Loading environment variables..."
	echo "Uploading all files in output directory to remote server..." && \
	rsync -avz --progress output/* $(SSH_USER)@$(SSH_HOST):$(REMOTE_PATH) && \
	echo "Upload complete."

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -rf output/**

# Help
.PHONY: help
help:
	@echo "Makefile commands:"
	@echo "  all              Build both backend and frontend"
	@echo "  build            Build the tool"
	@echo "  upload           Upload the backend binary to the remote server"
	@echo "  clean            Clean build artifacts"
	@echo "  help             Show this help message"