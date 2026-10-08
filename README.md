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

## Staff portal demo

Open **Staff portal** on the website and use one of these fictional accounts:

- Admin: `admin@infinite-demo.test` / `Admin123!`
- Employee: `alex.rivera@example.test` / `Staff123!`

The admin demo includes a staff directory, salary records, expenses, schedules, daily task assignments, and submitted work reports. The employee demo includes assigned tasks, time in/time out, schedule visibility, and reports with optional photo/video attachments.

## Prototype limitations

This is a static front-end demo. Sign-in credentials are visible in the page, role checks are not secure, and records are stored only in the current browser. Report attachments are previewed locally for the current session and are not uploaded. Do not use real employee, payroll, expense, schedule, or customer information. A production portal needs a server-backed identity system with role-based authorization, secure database storage, and protected media upload/access before handling real staff data.