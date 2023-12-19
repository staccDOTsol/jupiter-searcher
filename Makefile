# include .env file and export its env vars
# (-include to ignore error if it does not exist)
-include .env

.PHONY: build publish

# Variables


check_docker_env:
ifeq ($(strip $(DOCKERHUB_ORGANIZATION)),)
	$(error DOCKERHUB_ORGANIZATION is not set)
else
	@echo DOCKERHUB_ORGANIZATION: jrsdunn
endif

# Default make task
all: anchor_sync build

anchor_sync :; anchor keys sync
anchor_build :; anchor build

build: anchor_build docker_build measurement

build-basic-function: check_docker_env
	docker buildx build --pull --platform linux/amd64 \
		-f ./switchboard-functions/jupiter-searcher/Dockerfile \
		-t jrsdunn/jupiter-searcher:latest \
		./

publish-basic-function: check_docker_env
	docker buildx build --pull --platform linux/amd64 \
		-f ./switchboard-functions/jupiter-searcher/Dockerfile \
		-t jrsdunn/jupiter-searcher:latest \
		--push \
		./

build-basic-function2: check_docker_env
	docker buildx build --pull --platform linux/amd64 \
		-f ./switchboard-functions/savings_game/Dockerfile \
		-t jrsdunn/savings-game:latest \
		./

publish-basic-function2: check_docker_env
	docker buildx build --pull --platform linux/amd64 \
		-f ./switchboard-functions/savings_game/Dockerfile \
		-t jrsdunn/savings-game:latest \
		--push \
		./
build: docker_build measurement

publish: build-basic-function measurement

measurement: check_docker_env
	@docker run -d --platform=linux/amd64 -q --name=my-switchboard-function \
		jrsdunn/savings-game:latest > /dev/null
	@docker cp my-switchboard-function:/measurement.txt measurement.txt
	@echo -n 'MrEnclve: '
	@cat measurement.txt
	@docker stop my-switchboard-function > /dev/null
	@docker rm my-switchboard-function > /dev/null

docker_build: check_docker_env
	docker buildx build --builder cloud-switchboardlabs-default --pull --platform linux/amd64 \
		-f ./switchboard-functions/jupiter-searcher/Dockerfile \
		-t jrsdunn/jupiter-searcher:latest \
		./switchboard-functions/jupiter-searcher
docker_publish: check_docker_env
	docker buildx build --builder cloud-switchboardlabs-default --pull --platform linux/amd64 \
		-f ./switchboard-functions/jupiter-searcher/Dockerfile \
		-t jrsdunn/jupiter-searcher:latest \
		--push \
		./switchboard-functions/jupiter-searcher
