# LLM Sentinel Makefile
.PHONY: help install test test-unit test-cov lint dev-backend dev-frontend run-mock-demo clean

help:
	@echo "Available commands:"
	@echo "  make install       Install backend and frontend dependencies"
	@echo "  make test          Run full test suite"
	@echo "  make test-unit     Run backend unit tests"
	@echo "  make test-cov      Run pytest with coverage report"
	@echo "  make dev-backend   Start FastAPI development server"
	@echo "  make dev-frontend  Start Vite development server"
	@echo "  make clean         Clean cache and temporary files"

install:
	cd backend && python -m venv .venv && .\.venv\Scripts\pip install -e .[dev]
	cd frontend && npm install

test:
	cd backend && .\.venv\Scripts\pytest tests -v

test-unit:
	cd backend && .\.venv\Scripts\pytest tests/unit -v

test-cov:
	cd backend && .\.venv\Scripts\pytest tests --cov=app --cov-report=term-missing

dev-backend:
	cd backend && .\.venv\Scripts\uvicorn app.main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

clean:
	rmdir /s /q .pytest_cache
	del sentinel.db
