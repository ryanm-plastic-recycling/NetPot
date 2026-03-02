install:
	pip install -r requirements-dev.txt

dev:
	python -m honeysentinel config.yaml

test:
	pytest -q

lint:
	ruff check .
	mypy honeysentinel

format:
	ruff check . --fix

run:
	python -m honeysentinel config.yaml

docker-up:
	docker compose up --build
