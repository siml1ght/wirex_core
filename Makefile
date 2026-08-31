HYDRA_NKOBOX_DIR ?= ../nekobox
HYDRA_RESOURCE_DIRS := $(HYDRA_NKOBOX_DIR)/resources/bin $(HYDRA_NKOBOX_DIR)

GOBUILD := go build -trimpath -ldflags "-s -w"

.PHONY: all build-client build-server clean

all: build-client

## build-client — windows/amd64 hydra-client.exe straight into the nekobox resource tree
build-client:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -o hydra-client.exe ./cmd/client
	@for dir in $(HYDRA_RESOURCE_DIRS); do \
		if [ -d "$$dir" ]; then \
			cp -f hydra-client.exe "$$dir/hydra-client.exe" && \
			echo "installed: $$dir/hydra-client.exe"; \
		fi \
	done
	@if [ ! -f "$(firstword $(HYDRA_RESOURCE_DIRS))/hydra-client.exe" ] && [ ! -f "$(HYDRA_NKOBOX_DIR)/hydra-client.exe" ]; then \
		echo "NOTE: $(HYDRA_NKOBOX_DIR) not found — hydra-client.exe left in the repo root"; \
	fi

## build-server — linux/amd64 hydra-server for a VPS
build-server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GOBUILD) -o hydra-server ./cmd/server

clean:
	rm -f hydra-client.exe hydra-server hydra-server.exe
