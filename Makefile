# LLM Sentinel Makefile
.PHONY: help install test test-unit test-cov lint dev-backend dev-frontend docker-build docker-up docker-down clean

help:
	@echo "Available commands:"
	@echo "  make install       Install backend and frontend dependencies"
	@echo "  make lint          Run Ruff linter on backend"
	@echo "  make test          Run full test suite (43 tests, zero credentials required)"
	@echo "  make test-unit     Run backend unit tests"
	@echo "  make test-cov      Run pytest with coverage report"
	@echo "  make dev-backend   Start FastAPI development server"
	@echo "  make dev-frontend  Start Vite development server"
	@echo "  make docker-build  Build Docker containers for backend and frontend"
	@echo "  make docker-up     Start services with Docker Compose"
	@echo "  make docker-down   Stop Docker Compose services"
	@echo "  make clean         Clean cache and temporary files"

install:
	cd backend && python -m venv .venv && .\.venv\Scripts\pip install -e .[dev]
	cd frontend && npm install

lint:
	.\backend\.venv\Scripts\ruff.exe check backend

test:
	.\backend\.venv\Scripts\pytest backend/tests -v

test-unit:
	.\backend\.venv\Scripts\pytest backend/tests/unit -v

test-cov:
	.\backend\.venv\Scripts\pytest backend/tests --cov=backend/app --cov-report=term-missing

dev-backend:
	cd backend && .\.venv\Scripts\uvicorn app.main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rmdir /s /q .pytest_cache
	del sentinel.db
