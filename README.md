# Lantern Discovery Assistant

Lantern's internal proof of concept for turning interview notes into an editable requirements summary and prototype plan. The frontend uses React, Vite, and Tailwind CSS; the Python standard-library server provides the API and serves the prebuilt frontend. It also supports human review, Word/PDF exports, version history, simple clickable sample prototypes, CSV imports, feedback-based revisions, and a technical handoff draft.

## Start locally

1. Extract the ZIP and open the `lantern-discovery` folder.
2. Install Python 3.9 or later.
3. Double-click `run.bat`, or run `python app.py` in a terminal from this folder. Open `http://127.0.0.1:8000` if the browser does not open.
4. **Try local demo** works without an API key. For real AI output, copy `.env.example` to `.env`, add an OpenAI API key and restart the server. API access/credits are separate from ChatGPT.

No Python packages or Node.js installation are needed to run the extracted release ZIP. It includes the compiled React/Tailwind frontend in `dist/`.

## Develop the React frontend in VS Code

Install Node.js 20.19 or later. Open the project folder in VS Code, then open two terminals:

1. In terminal one, start the Python API with `python app.py`.
2. In terminal two, run `npm install` once, then `npm run dev`.
3. Open the Vite address shown in terminal two, usually `http://127.0.0.1:5173`.
4. Before sharing a ZIP or deploying, run `npm run build`. The Python server and Docker image serve the resulting `dist/` folder.

The discovery interface is mounted by React. Its existing workflow controller remains in `src/legacy.js` as a migration bridge so the current features stay available while the screens are moved into React components over time. Tailwind utilities are compiled locally; no Tailwind CDN is required at runtime.

## Put the project on GitHub

Use a **private** GitHub repository for this internal tool. In VS Code, open this folder, click **Source Control**, choose **Initialize Repository**, review the file list, enter a commit message, and choose **Publish to GitHub**. Select **Private** when VS Code asks for visibility. The `.gitignore` keeps `.env`, saved records in `data/`, and `node_modules/` out of Git. Confirm none of those appear in the staged file list before publishing.

GitHub stores and shares the source code; it does not run the app as a website. Colleagues can clone the repository and run `run.bat` locally. Live shared access still needs the private server deployment described in [DEPLOYMENT.md](DEPLOYMENT.md).

## Shared accounts

Local mode stores records on one computer and has no sign-in. To enable a shared hosted workspace, use the single-server pilot setup in [DEPLOYMENT.md](DEPLOYMENT.md). In team mode, the first administrator is configured with `.env`; that administrator can create named accounts with analyst, reviewer, or admin roles. All users share the server's saved project records. Reviewers can approve assigned projects. Admins manage accounts, full backups, data-retention settings, and archive/delete actions.

The deployment guide describes the current pilot limits and required HTTPS, persistent storage, and backup setup. The hosted version should stay private to Lantern and behind a trusted HTTPS reverse proxy; it is not a public website.

## Working with discovery records

- Choose a general, clinic, or retail question template, or import a response CSV downloaded from Google Forms. Check answers before generation.
- The local demo makes clearly labeled template drafts without an AI call. Live generation and AI-assisted revisions require OpenAI API access.
- Review the assumptions, missing answers, and source references. Edit the documents and approve only after a Lantern team member has checked them.
- Save projects to keep their version and activity history. The current project files and account database live in `data/` locally or the mounted `/data` folder when deployed.
- Download one or all available documents as Word or PDF. The prototype HTML uses fictional sample data and is not a production application.
- Backups contain interview answers and generated documents. Keep them private and encrypted. The application ZIP does not include `.env` or local client records.

## Privacy

Use fictional information while exploring the proof of concept. Do not send confidential client or personal data to an AI service until Lantern has agreed on an appropriate privacy and security approach. The app requires an explicit consent checkbox before it sends interview content for AI analysis.

See [START-HERE.txt](START-HERE.txt) for quick local steps and [DEPLOYMENT.md](DEPLOYMENT.md) before enabling team mode.
