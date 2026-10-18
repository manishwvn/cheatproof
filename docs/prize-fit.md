# Prize fit (rule text only; re-check the rules page before submitting)

Sources: nebiusglobalaihackathon.devpost.com overview, /rules, /resources, /details/faqs, /updates, /forum_topics
(read 2026-10-16).

## Dates (Pacific)
- Submission period: Aug 26 2026 09:00 to **Oct 30 2026 10:00 PDT**.
- Judging: Dec 1 09:00 to Dec 15 2026 12:00 PST. Winners: around Jan 11 2027.
- The project must stay available, free, for judges until judging ends (Dec 15).

## Prizes and stacking
| Prize | Amount | Count |
|---|---|---|
| Grand / 2nd / 3rd | $20,000 / $10,000 / $6,000 | 1 each |
| Track winner (each of 4 tracks) | NVIDIA Jetson Orin Nano | 1 each |
| Best Use of Tavily (bonus) | $3,000 | 1; needs a functional runtime Tavily API call |
| City Winner (bonus) | $500 | 20; needs in-person Builders & Brews attendance (all events are over) |
| Most Valuable Feedback | $100 + NVIDIA swag | 10; judged on completeness, viability, impact of feedback |

Rule: "Each Project is eligible for one (1) Overall Award OR one (1) Track Award and one (1) Bonus Award."
The manager confirmed an Overall winner cannot also take a Bonus Award. Multiple submissions are allowed if each is
substantially different. There is no team-size cap.

## Judging
- Stage 1, pass/fail: fits the track (a genuine attempt, not a rebrand) and reasonably applies the required tech.
- Stage 2: four equally weighted criteria, each scored 1–5: **Technological Implementation** (use of Token Factory or
  AI Cloud plus NVIDIA models), **Design** (complete product, not a PoC), **Potential Impact** (credible real problem
  and audience, demonstrated), **Quality of the Idea** (creative, non-obvious, understands the problem space).
- Ties are broken by criterion order (Tech Implementation first).
- Judges may judge only from the text, images and video; assume they do.

## Hard requirements
- "Runs on Nebius" means a runtime call to the Token Factory inference API, or deployment on Nebius AI Cloud
  (Serverless Jobs/Endpoints, DevPods). Using NVIDIA models through other providers does not count.
- At least one NVIDIA open-source model (Nemotron, GR00T, Cosmos, Sonic; Alpamayo allowed).
- Working demo URL, or a test build (login credentials in the instructions if private).
- Public YouTube video under 3 min with no unlicensed third-party trademarks or music.
- Public GitHub repo with an open-source license visible in the About box. README with setup and run steps, and how
  Nemotron, Token Factory and other Nebius tools are used.
- Feedback on Token Factory, AI Cloud and NVIDIA tools (required field). English. Original work.
- If the project predates Aug 26, explain what changed (not applicable: new project).

## Eligibility (rule text)
Age of majority where the entrant lives; excludes Brazil, Quebec, Russia, Crimea, Cuba, Iran, North Korea and other
OFAC-sanctioned places. Also excludes employees, families and households of the Sponsor (Nebius), the Administrator
(Devpost), and any company employing a judge (NVIDIA and Tavily employ judges).

## Sponsor tools
- Token Factory: OpenAI-compatible, `https://api.tokenfactory.nebius.com/v1/`. A card is required to set up billing.
  The balance is prepaid via top-up, but it can go negative, and the card is auto-charged at month start or at a
  "configured billing threshold". There is no documented hard spend cap, so the in-app cap in `cheatproof/budget.py`
  ($20 total) is mandatory.
- Credits: $25 via the activation code `NEBIUS-DEVPOST-GLOBAL26`, entered on the promo form opened through the Devpost
  Resources page link (event code `2026-devpost-global-ai-hack`; the bare https://nebius.com/promo-code URL errors with
  "no event name found"). The form emails the real promo code (then Balance → Top up → With promo code). A new
  account starts with a $1 trial balance. The Nebius Builders Program may add $25
  (expires 90 days after issue; unreliable, so the plan assumes $25). Tavily promo `BBDEVPOST`.
- Sandboxes (beta): access via `tokenfactory.nebius.com/sandboxes/about` or contree@nebius.com. 50 concurrent ops.
  Networking can only be on or off. Only stdout/stderr are captured. Root in the VM. Per-run price not documented.
- Post-training does not support Nemotron models.

## The bar (signals from organiser updates and forum only)
The organisers say to push past the basics: an agent that plans, writes, tests and iterates on a real repo. Name the
required tools in the description, in "Built with" and out loud in the video. Never put keys in the repo. Many
entrants are blocked on billing.
