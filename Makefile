build:
	docker build -t dns-proxy .

check:
	black --check *.py
	pylint -d missing-docstring --fail-under 9 *.py


run:
	docker-compose up -d
