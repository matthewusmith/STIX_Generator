# STIX Workbench — user guide

A browser UI for the STIX Generator pipeline: upload a threat intelligence report, watch it run,
check every extracted entity and relationship against the source text, correct what's wrong, and
save the result as a gold-standard file.

Everything runs on your own machine. Nothing is uploaded anywhere except the report text, which
goes to the Anthropic API exactly as it already does when you run the pipeline from the notebook
or command line.

---

## The pieces

| File | What it is | Where it goes |
| --- | --- | --- |
| `STIX Workbench (standalone).html` | The whole UI in one file. No install, no build step. | repo root |
| `server.py` | Local web server. Wraps the existing pipeline in HTTP endpoints and serves the UI. | repo root |
| `api-spec.md` | The endpoint contract, for whoever maintains the server. | reference only |
| `stix_generator/` | Your pipeline. **Unchanged** — the server only calls into it. | already there |

The UI works in two modes:

- **Connected** — `server.py` is running, so uploads, extraction, editing and gold files are all real.
- **Offline** — you opened the HTML by itself. It loads a sample extraction baked into the file so
  you can click around, but nothing can be uploaded or saved. Useful for showing someone the tool.

The header tells you which you're in: a green dot and **server connected**, or a grey **offline · embedded IR**.

---

## First-time setup

You only do this once.

### 1. Put the two files in the repo folder

`STIX Workbench (standalone).html` and `server.py` both go in the `STIX_Generator` folder — the same
folder that contains `stix_generator\` and `data\`. Not in a subfolder.

### 2. Open a terminal there

In File Explorer, navigate to the `STIX_Generator` folder, click the address bar at the top, type
`powershell`, and press Enter.

### 3. Install the three extra packages

```
.venv\Scripts\pip.exe install fastapi uvicorn python-multipart
```

These are only needed for the web server. The pipeline itself already has everything it needs.

### 4. Confirm your API key is set

The server reads `ANTHROPIC_API_KEY` from the `.env` file in this folder, the same as the notebook
does. If extraction already works for you, this is already done.

---

## Every time you want to use it

### Start the server

```
.venv\Scripts\python.exe server.py
```

You'll see a line like `Uvicorn running on http://127.0.0.1:8000`. **Leave this window open** — closing
it shuts the server down.

### Open the UI

Go to **http://localhost:8000** in your browser.

### Stop when you're done

Click the terminal window and press **Ctrl + C**.

---

## The screen

Four regions, left to right:

**Runs rail** — every report you've submitted this session, newest first, with live status. Click a run
to open it.

**Source text** — the report as `load_report()` extracted it. The evidence quote for whatever you have
selected is highlighted here.

**Extraction list** — everything the model found, grouped by type, with tabs across the top.

**Inspector** — the selected item's full detail, and where you edit it.

---

## Running a report

1. Click **+ report** in the rail (or the dashed drop area below it).
2. The run config appears. Two switches:
   - **critic** — one extra API call that re-reads the entity draft for things it missed or invented.
     Improves recall on *entities*. Off by default.
   - **verifier** — pass C. Judges every relationship the model proposed as supported, downgrade, or
     unsupported, and drops the unsupported ones. Improves precision on *relationships*. On by default;
     turn it off only when you're measuring two-pass against three-pass.
3. Click **choose report…** and pick a `.pdf`, `.txt`, or `.md` file. Anything else is rejected
   immediately, before any API spend.
4. The run appears in the rail and moves through its stages: `queued → loading → extracting →
   building → validating → ready`. Extraction is the slow part — 20 to 60 seconds depending on report
   length and whether critic is on.

When it reaches `ready` the extraction loads automatically.

### If a run fails

The rail row turns red and tells you why:

- **rejected** — wrong file type. Convert it to PDF or plain text.
- **truncated** — the report is too long for the model's output limit; it retried three times and gave
  up. The report needs splitting, or `MAX_TOKENS_CEILING` in `extractor.py` needs raising.
- **failed** — anything else. The full traceback is in the terminal window.

---

## Reviewing an extraction

This is the main job: confirming that each thing the model found is actually in the report.

Click any row in the extraction list. Three things happen at once — the row's evidence quote is
highlighted in the source text on the left, the inspector fills in on the right, and the map
(if you're on that tab) centres on it.

**The coloured dot** on each row is grounding status:

- **green** — the model's evidence quote was found verbatim in the report. The claim is anchored.
- **amber** — the quote could not be found. This does *not* automatically mean the model made it up;
  it often means the model paraphrased something real, or the PDF text extraction mangled the line.
  It means *you* have to look. Every amber row deserves a read.

The **unverified** filter above the list shows you only those. That's the queue.

Use **keep** and **drop** in the inspector to record your judgement. The counter in the header tracks
how far through you are. Dropped items are excluded from the gold file but stay visible (faded) so the
count stays honest.

### Reading the relationship rows

Relationships show their pass C verdict:

- **supported** — the verifier found text backing the relationship as stated.
- **downgraded** — the text supported something weaker, so the verb was replaced. The row shows the new
  verb, with the original struck through.
- Relationships judged unsupported were already dropped before you saw them; they're listed in the
  **VALIDATION** tab under extraction notes, so nothing disappears silently.

---

## Correcting an extraction

Every edit updates the IR in memory and is saved back to the server automatically about a second later.
There is no save button for edits — only for promoting the whole thing to a gold file.

**Rename, re-describe, add aliases** — type in the inspector fields.

**Change an entity's type** — click a different chip in the TYPE row. This is the most common
correction: tools misfiled as malware, infrastructure filed as tools.

**Merge two entities that are the same thing** — select one, then pick the other from **MERGE INTO**.
The names fold into the survivor's alias list, every relationship rewires to it, and the duplicate's
`local_id` disappears. Self-referencing relationships created by the merge are removed.

**Fix a relationship** — select it and use the three dropdowns: source, verb, target. Underneath them
a line tells you whether the triple is a spec pairing. If it isn't, it tells you what the builder will
emit instead — for example `threat-actor -exploits-> vulnerability` will be written as `targets`,
because that's what the STIX 2.1 spec allows. Green means it'll be emitted as you typed it; amber means
it'll be rewritten.

**Add something the model missed** — select the phrase in the source text on the left. A bar appears
offering **+ entity** and **+ observable**. The selected text becomes the new item's evidence quote, so
it's grounded by construction. Set its type and name in the inspector.

**Add a missing relationship** — the **+ add** button in the RELATIONSHIPS group header. It creates a
`related-to` between the first two items; change the endpoints and verb in the inspector.

**Delete a relationship** — the **delete** button in its inspector.

### Filters

Above the list: **all**, **unverified**, **downgraded**, **edited**, **dropped**. `edited` is the most
useful on a second pass — it shows only what you've touched.

---

## The other tabs

**GOLD IR** — the corrected extraction as it will be written, live. This is the same shape as the files
in `data\golden\` and the `.extraction.json` files the pipeline writes, so it's directly comparable.

**VALIDATION** — the STIX 2.1 schema result for the built bundle, the extraction notes from pass C and
grounding, and a pairing check listing every relationship the builder will rewrite.

**MAP** — the relationship graph, laid out in columns: actor and campaign, TTPs, tooling, infrastructure
and targets, observables. Built from the live IR, so anything you add appears immediately. Click a node
to select it. The source pane and inspector collapse on this tab to give the graph room.

---

## Saving a gold file

Click **save as golden ↓** in the header. The corrected IR is written to
`data\golden\<report-name>.json`.

Two important things about gold files:

1. **A gold file is ground truth.** It's what accuracy is measured against, so it needs to be right.
   Work through the whole extraction — every amber row read, every type checked — before saving one.
   A gold file saved from an unreviewed extraction just measures the model against itself.
2. **They're plain JSON.** You can hand-edit them later in any text editor if you spot something.

Once you have a gold file, score any run against it from the command line as you always have:

```
.venv\Scripts\python.exe -m stix_generator.evaluation data\reports\<report>.pdf --golden data\golden\<name>.json
```

Or, since the pipeline now saves the IR alongside the bundle, re-score without paying for another
extraction:

```
.venv\Scripts\python.exe -m stix_generator.evaluation data\reports\<report>.pdf --from-extraction data\output\<report>.extraction.json --golden data\golden\<name>.json
```

---

## Sharing the UI with someone

Send them just `STIX Workbench (standalone).html`. They double-click it and it opens in any browser
with a sample extraction loaded — no Python, no install, no server. They can click through the whole
interface, but they can't upload a report or save anything. That needs the server, which needs the
repo and an API key.

---

## Where files end up

| Path | What lands there |
| --- | --- |
| `data\reports\` | reports you upload through the UI |
| `data\output\<name>.json` | the STIX 2.1 bundle |
| `data\output\<name>.extraction.json` | the IR, for re-scoring and re-building with no API call |
| `data\golden\<name>.json` | gold files you save from the UI |

---

## Troubleshooting

**Header says "offline · embedded IR" but the server is running** — you opened the HTML file directly
instead of going to `http://localhost:8000`. Use the URL.

**"put the workbench HTML at STIX Workbench (standalone).html"** — the HTML file isn't in the same
folder as `server.py`, or it got renamed. The name must match exactly.

**`ModuleNotFoundError: No module named 'fastapi'`** — the install step didn't run, or ran against a
different Python. Re-run it with the full `.venv\Scripts\pip.exe` path from inside the repo folder.

**`ModuleNotFoundError: No module named 'stix_generator'`** — you started the server from the wrong
folder. `cd` into `STIX_Generator` first.

**An error mentioning `ANTHROPIC_API_KEY`** — the `.env` file is missing or doesn't have your key.

**A run sits at "extracting" for minutes** — long reports with critic on can take over a minute. Watch
the terminal window; it prints each pass as it completes, with token counts. If it's genuinely stuck,
Ctrl + C and restart.

**Edits don't seem to stick** — they save about a second after you stop typing. If the header keeps
saying "unsaved edits", the server connection dropped; check the terminal window is still running.

**Two people editing the same run** — last write wins, silently. Don't. It's a single-analyst tool
until someone adds locking.
