.PHONY: help install install-dev run run-dev test lint format clean docker-build docker-run setup-db train-models

help:
	@echo "Available commands:"
	@echo "  install      - Install production dependencies"
	@echo "  install-dev  - Install development dependencies"
	@echo "  run          - Run the application"
	@echo "  run-dev      - Run in development mode with hot reload"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"
	@echo "  clean        - Clean up temporary files"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  setup-db     - Initialize database"
	@echo "  train-models - Train ML models"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt -r requirements-dev.txt
	pre-commit install

run:
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000

run-dev:
	uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

test:
	pytest tests/ -v --cov=src --cov-report=html

lint:
	flake8 src/ tests/
	mypy src/

format:
	black src/ tests/
	isort src/ tests/

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/

docker-build:
	docker build -t ai-phishing-detector .

docker-run:
	docker-compose up -d

setup-db:
	python scripts/setup.py --init-database

train-models:
	python scripts/train_models.py --quick-setup
