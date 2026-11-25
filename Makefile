# On Windows without make, run the same commands by hand (see README.md).
ifeq ($(OS),Windows_NT)
PY = .venv/Scripts/python
else
PY = .venv/bin/python
endif

.PHONY: data baseline run inject eval app test

data:
	$(PY) -m src.gen_synthetic
	$(PY) -m src.load_public
	$(PY) -m src.make_splits
	$(PY) -m src.build_injection_set

# The baseline needs no model; its tables are part of eval.
baseline: eval

run:
	$(PY) -m src.pipeline --split dev --set clean --guard off
	$(PY) -m src.pipeline --split dev --set clean --guard on

inject:
	$(PY) -m src.pipeline --split dev --set inject --guard off
	$(PY) -m src.pipeline --split dev --set inject --guard on

eval:
	$(PY) -m src.evaluate

app:
	@echo "app.py is P1 and not written yet"

test:
	$(PY) -m pytest -q
