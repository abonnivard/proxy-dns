

build:
	docker build -t dns-proxy .

create_env:
	python3 -m venv env && . env/bin/activate  && pip install -r requirements.txt

check: create_env
	. env/bin/activate && black --check *.py && pylint -d missing-docstring --fail-under 9 *.py


run:
	docker-compose up -d
