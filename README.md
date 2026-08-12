# STIX Generator

Turns narrative cyber threat intelligence reports (PDF/text) into STIX 2.1 bundles using Claude, then validates the result against the official schema.

## Getting the code

This repo includes the official STIX 2.1 schemas as a **git submodule**, so a plain clone leaves that folder empty. Clone it like this instead:

```
git clone --recurse-submodules https://github.com/matthewusmith/STIX_Generator.git
```

Already cloned without `--recurse-submodules`? Run this from inside the folder to fetch it after the fact:

```
git submodule update --init
```

## Running the interactive notebook (`phase1_walkthrough.ipynb`)

This is the easiest way to run and experiment with the pipeline — no command-line Python knowledge required beyond following these steps. Jupyter Lab and this project's dependencies are already installed and set up for you; you're just launching a program and clicking things.

### 1. Open a terminal in this folder

- In File Explorer, navigate to this `STIX_Generator` folder.
- Click the address bar at the top, type `powershell`, and press Enter. A blue terminal window opens, already pointed at this folder.

  (Alternative: hold Shift, right-click inside the folder, and choose "Open PowerShell window here.")

### 2. Start Jupyter Lab

In the terminal window, type this and press Enter:

```
.venv\Scripts\jupyter-lab.exe
```

A bunch of text will scroll by, and then your web browser should automatically open a new tab showing Jupyter Lab — a file browser and notebook editor running locally on your own machine (nothing is uploaded anywhere).

**Leave the terminal window open** while you work — closing it shuts down Jupyter Lab. If the browser tab doesn't open automatically, look in the terminal output for a line like `http://localhost:8888/lab?token=...` and copy/paste that whole URL into your browser.

### 3. Open the notebook

In the file browser panel on the left side of the Jupyter Lab window, double-click **`phase1_walkthrough.ipynb`**.

### 4. Check the kernel (important)

Look at the top-right corner of the notebook. It should say **"STIX Generator (.venv)"**. This tells Jupyter which Python environment to run your code in — the one with all this project's dependencies already installed.

- If it already says that, you're good — skip to step 5.
- If it says something else (like "Python 3" or "No Kernel"), click on that text, and in the dropdown that appears, choose **"STIX Generator (.venv)"**.

### 5. Run the notebook

Each notebook is a sequence of "cells" — some are just text/explanation (markdown), others contain runnable code. To run the whole thing top to bottom:

- Use the menu: **Run → Run All Cells**

Or run cells one at a time to see each step's output as you go:

- Click on the first code cell, then press **Shift + Enter**. This runs that cell and moves you to the next one.
- Repeat Shift + Enter down through the notebook.

As cells run, you'll see output appear directly underneath them — text, lists, JSON, etc.

### What it costs / how long it takes

Almost everything in the notebook is instant and free (it's just Python code running on your machine). The one exception is the cell that calls `extract(...)` — that's the step that sends the report to Claude and costs a small amount on your API account. It typically takes 10–40 seconds. Everything before and after that cell can be re-run freely at no cost.

### Stopping Jupyter Lab when you're done

Close the browser tab, then go back to the terminal window and press **Ctrl + C** twice (it'll ask you to confirm shutdown).

## Troubleshooting

**"ModuleNotFoundError: No module named 'stix_generator'"** — the notebook isn't using the right kernel, or Jupyter Lab was launched from the wrong folder. Confirm the kernel (step 4 above) says "STIX Generator (.venv)", and confirm you ran `.venv\Scripts\jupyter-lab.exe` from *inside* this `STIX_Generator` folder.

**An error mentioning `ANTHROPIC_API_KEY`** — this project reads your API key from a file named `.env` in this folder (not committed/shared anywhere). Confirm `.env` exists here and contains a line like `ANTHROPIC_API_KEY=sk-ant-...` with your real key.

**Kernel dropdown doesn't show "STIX Generator (.venv)" at all** — the kernel wasn't registered, or Jupyter Lab needs a restart to notice it. Close Jupyter Lab (Ctrl+C in the terminal) and reopen it.

**You renamed/moved this folder again** — the kernel and some installed command shortcuts remember the exact folder path they were set up with. If you move this folder, dependencies need to be reinstalled and the kernel re-registered from the new location; ask your assistant to redo that setup rather than trying to fix it by hand.

## Running from the command line instead

If you'd rather run the whole pipeline in one shot without the notebook:

```
.venv\Scripts\python.exe -m stix_generator.pipeline data\reports\<your-report>.pdf --out data\output\<name>.json
```

## Project layout

- `stix_generator/` — the actual pipeline code (ingestion → extraction → construction → validation)
- `data/reports/` — put source PDF/text reports here
- `data/output/` — generated STIX bundles land here
- `phase1_walkthrough.ipynb` — the interactive notebook described above
- `third_party/cti-stix2-json-schemas/` — official STIX 2.1 JSON schemas, included as a git submodule (see note in `stix_generator/validation/validator.py` for why); see "Getting the code" above if this folder looks empty
