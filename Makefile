ifeq ($(OS),Windows_NT)
    # Configuration pour Windows
    ACTIVATE_CMD = . env/Scripts/activate
    CMD = start cmd /k
    ENV_CMD = call env/Scripts/activate
else ifeq ($(shell uname),Darwin)
    # Configuration pour macOS avec iTerm2
    ACTIVATE_CMD = . env/bin/activate
    CMD = open -a iTerm --args
    END_CMD = "; exec bash"
    ENV_CMD = . env/bin/activate
else
    # Configuration pour Linux
    ACTIVATE_CMD = . env/bin/activate
    CMD = gnome-terminal -- /bin/sh -c
    END_CMD = ; exec bash
    ENV_CMD = . env/bin/activate
endif

all: setup install run_index run
prepare: setup install

setup:
	python3 -m venv env

install:
	$(ACTIVATE_CMD) && pip install -r requirements.txt && pip install --upgrade pip

run:
	$(ACTIVATE_CMD) && python proxy.py

run_index:
	$(CMD) "$(MAKE) prepare && $(ENV_CMD) && python gestion_index.py $(END_CMD)"
