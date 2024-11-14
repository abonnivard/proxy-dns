build:
	docker build -t dns-proxy .

check:
	black --check *.py
	pylint -d missing-docstring *.py


run:
	docker-compose up -d
