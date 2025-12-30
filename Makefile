.PHONY: help install run test docker-build docker-run deploy clean

# Configuration
PROJECT_ID ?= your-gcp-project-id
REGION ?= us-central1
SERVICE_NAME ?= github-app-token-service
IMAGE_NAME ?= $(SERVICE_NAME)
IMAGE_TAG ?= latest
FULL_IMAGE_NAME = gcr.io/$(PROJECT_ID)/$(IMAGE_NAME):$(IMAGE_TAG)

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

run: ## Run the application locally with uvicorn
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test: ## Run tests with pytest
	pytest -v

docker-build: ## Build Docker image
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run: ## Run Docker container locally
	docker run -p 8080:8080 \
		-e APP_ENV=dev \
		-e PORT=8080 \
		$(IMAGE_NAME):$(IMAGE_TAG)

docker-build-gcr: ## Build and tag Docker image for GCR
	docker build -t $(FULL_IMAGE_NAME) .

docker-push: ## Push Docker image to GCR
	docker push $(FULL_IMAGE_NAME)

build-cloud: ## Build image using Cloud Build
	gcloud builds submit --tag $(FULL_IMAGE_NAME) --project $(PROJECT_ID)

deploy: ## Deploy to Cloud Run (requires PROJECT_ID)
	@if [ "$(PROJECT_ID)" = "your-gcp-project-id" ]; then \
		echo "Error: Please set PROJECT_ID variable (e.g., make deploy PROJECT_ID=my-project)"; \
		exit 1; \
	fi
	@echo "WARNING: Deploying with placeholder GitHub credentials."
	@echo "The service will start but GitHub integration will not work."
	@echo "Use 'make deploy-with-secrets' to deploy with real credentials."
	gcloud run deploy $(SERVICE_NAME) \
		--image $(FULL_IMAGE_NAME) \
		--platform managed \
		--region $(REGION) \
		--no-allow-unauthenticated \
		--set-env-vars="^##^APP_ENV=prod##GCP_PROJECT_ID=$(PROJECT_ID)##REGION=$(REGION)" \
		--set-env-vars="GITHUB_APP_ID=placeholder" \
		--set-env-vars="GITHUB_PRIVATE_KEY=placeholder" \
		--set-env-vars="GITHUB_CLIENT_ID=placeholder" \
		--set-env-vars="GITHUB_CLIENT_SECRET=placeholder" \
		--set-env-vars="GITHUB_WEBHOOK_SECRET=placeholder" \
		--project $(PROJECT_ID)

deploy-with-secrets: ## Deploy to Cloud Run with secrets from environment
	@if [ "$(PROJECT_ID)" = "your-gcp-project-id" ]; then \
		echo "Error: Please set PROJECT_ID variable (e.g., make deploy PROJECT_ID=my-project)"; \
		exit 1; \
	fi
	@if [ -z "$(GITHUB_APP_ID)" ] || [ -z "$(GITHUB_PRIVATE_KEY)" ] || [ -z "$(GITHUB_CLIENT_ID)" ] || [ -z "$(GITHUB_CLIENT_SECRET)" ] || [ -z "$(GITHUB_WEBHOOK_SECRET)" ]; then \
		echo "Error: One or more required GitHub secret environment variables are not set."; \
		echo "Required: GITHUB_APP_ID, GITHUB_PRIVATE_KEY, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_WEBHOOK_SECRET"; \
		echo "Please source your .env file or export them manually."; \
		exit 1; \
	fi
	gcloud run deploy $(SERVICE_NAME) \
		--image $(FULL_IMAGE_NAME) \
		--platform managed \
		--region $(REGION) \
		--no-allow-unauthenticated \
		--set-env-vars="^##^APP_ENV=prod##GCP_PROJECT_ID=$(PROJECT_ID)##REGION=$(REGION)" \
		--set-env-vars="GITHUB_APP_ID=$(GITHUB_APP_ID)" \
		--set-env-vars="GITHUB_PRIVATE_KEY=$(GITHUB_PRIVATE_KEY)" \
		--set-env-vars="GITHUB_CLIENT_ID=$(GITHUB_CLIENT_ID)" \
		--set-env-vars="GITHUB_CLIENT_SECRET=$(GITHUB_CLIENT_SECRET)" \
		--set-env-vars="GITHUB_WEBHOOK_SECRET=$(GITHUB_WEBHOOK_SECRET)" \
		--project $(PROJECT_ID)

invoke: ## Invoke the deployed Cloud Run service (authenticated)
	@if [ "$(PROJECT_ID)" = "your-gcp-project-id" ]; then \
		echo "Error: Please set PROJECT_ID variable"; \
		exit 1; \
	fi
	gcloud run services proxy $(SERVICE_NAME) --region $(REGION) --project $(PROJECT_ID)

logs: ## View Cloud Run service logs
	@if [ "$(PROJECT_ID)" = "your-gcp-project-id" ]; then \
		echo "Error: Please set PROJECT_ID variable"; \
		exit 1; \
	fi
	gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$(SERVICE_NAME)" \
		--limit 50 \
		--format json \
		--project $(PROJECT_ID)

clean: ## Clean up local artifacts
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete
