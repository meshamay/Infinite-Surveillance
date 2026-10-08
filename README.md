# Infinite Surveillance and Medical Solutions Co.

Company website with a staff-portal prototype in `index.html`.

## AI support chat

Run the site through the included local Python server so the chatbot can use its same-origin AI endpoint:

```sh
export OPENAI_API_KEY="your-provider-key"
python3 server.py
```

Then open `http://127.0.0.1:8000`. The key is read by the Python server and is never included in browser code. `OPENAI_MODEL` can optionally select another model supported by the OpenAI Responses API; the default is `gpt-4o-mini`. API usage may incur charges on the account associated with the key.

The server checks every latest user message against the website topics before it can reach the AI provider. Unrelated questions and attempts to override the assistant's instructions receive a fixed refusal. The AI is instructed to answer only from facts published on this site and not to invent missing prices, coverage, or policies. If the key is unset or the AI service is unavailable, the chat clearly switches to its built-in FAQ fallback. Chat messages are sent to the configured AI provider when AI is enabled. Avoid entering sensitive or confidential information. The included server binds to localhost and is for local development only; public deployment needs HTTPS, production-grade rate limiting, and a properly secured backend.

## Staff portal

Start the Python server with `python3 server.py` and open `http://127.0.0.1:8000`. On a new database, open **Staff portal** and create the first administrator account. Use a unique password of at least 12 characters. The setup endpoint closes permanently after the first admin is created.

Admins create employee accounts from the Staff tab. The server displays a randomly generated temporary password once; give it to that employee securely. Employees can sign in and change it from their workspace. Passwords are stored as salted PBKDF2 hashes. Sign-in sessions use expiring, HttpOnly, SameSite cookies.

Staff, attendance, payroll, expenses, schedules, tasks, work reports, and report attachments are stored by the server in SQLite and the private uploads directory under `data/`. The server filters employee results to their own records and restricts admin-only writes and report attachments. The `data/` directory is deliberately excluded from Git and blocked from static website access. Back up the complete `data/` directory regularly and store backups separately from this checkout.

This included Python server is a single-machine development server bound to localhost. Before using sensitive employee or payroll data in production, deploy behind HTTPS on a maintained production web server, set `PORTAL_COOKIE_SECURE=1`, configure a private persistent `PORTAL_DATA_DIR`, enforce organization-specific retention and access policies, and test backups/restores. Anyone who can administer the host or read its data directory can access the database and uploads. The app does not yet provide password-reset email, audit exports, or automated backup jobs.

Run backend integration tests with `python3 -m unittest -v test_portal_backend`.