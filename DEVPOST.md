# ScamShield Jr

## Required contest elements

### Intended user

A middle or high school student helping a grandparent decide what to do with a suspicious SMS, email or direct message.

### Situation or risk

The grandparent receives a message that sounds urgent, official or family related. The message may ask for money, a password, a one-time code, a gift card payment or secrecy from other relatives. The student wants to help but may not know how to explain which parts are manipulation.

### Practical improvement

ScamShield Jr turns the pasted synthetic message into visible evidence. It highlights exact phrases and header details, explains eight scam tactics in plain language and gives the student a short script to read aloud. The family practices pausing and verifying through a trusted route instead of reacting inside the message.

### One safer outcome

In the locked-account example, the student sees the countdown, credential request, mismatched sender domain and divergent reply-to domain highlighted. The student reads the script aloud, and the family calls the bank using the number printed on the physical card. No password, one-time code or payment goes to the synthetic attacker.

### One limitation

The offline prototype cannot inspect a live link, follow redirects or prove who controls the sender account. It never clears a message as safe. It always shows residual risk and the two checks it cannot make.

## Inspiration

Family scam messages often succeed because they create speed, secrecy and confusion at the same time. A grandparent may know that scams exist but still not know which exact phrase is the warning sign. ScamShield Jr treats the student as a calm helper and gives that student evidence they can point to.

## What it does

The prototype analyzes pasted synthetic SMS, email and direct-message examples offline. It detects urgency pressure, payment-rail switching, sender-domain mismatch, lookalike characters, reply-to divergence, risky attachment types, credential requests and family emergency scripts.

Every positive rule returns exact matched spans. The interface highlights those spans in the original evidence and pairs each tactic with a plain-language explanation and a next step. The risk summary never gives a binary safe verdict. Drill mode lets the student practice with six synthetic messages and grades correct marks, missed tactics, false alarms and category judgment.

## How it was built

The app is static HTML, CSS and JavaScript. The rule engine is shared between the browser and Node tests. It uses deterministic regular expressions, domain normalization, lookalike-character mapping, attachment extension rules and drill grading logic. There are no runtime dependencies, no API keys, no analytics and no network calls.

The test suite uses `node --test` on Node 22 or newer and contains 38 tests with 137 deterministic assertion statements. Headless-Chrome scripts capture screenshots and exercise the real interface.

## Challenges

The hardest part was avoiding a false sense of certainty. A keyword score can look authoritative even when it misses context. The design therefore treats every result as unverified evidence, names two checks the offline tool cannot make and keeps the read-aloud script focused on independent verification.

Domain comparison was another challenge. Subdomains can hide a fake root, lookalike characters can imitate a familiar name and reply-to domains can diverge quietly. The tests cover those edge cases directly.

## Accomplishments

The prototype is fully offline and still produces specific, inspectable evidence. It includes exact offsets, drill grading, malformed-input handling, deterministic scoring, browser checks, three real screenshots and a narrated demo video.

## What was learned

A family safety tool should teach judgment rather than pretend to replace it. Highlighting evidence and naming uncertainty is more useful than flashing a single red or green answer.

## What is next

Future versions could add printed practice sheets, multilingual explanations, more domain fixtures and a guided verification checklist. Any online version would need careful privacy design because pasted messages can contain sensitive personal information.

## Built with

HTML, CSS, JavaScript, Node.js, node test runner, headless Chrome and ffmpeg.

## Links

- Demo video is committed at `video/demo.mp4`
- Live prototype is at https://aariv.me/scamshield-jr/
- Source repository is at https://github.com/draarivpatel-ui/scamshield-jr

## AI disclosure

AI assistance was used to draft, implement, test and document this prototype. The running product does not use an AI model. Aariv Patel reviewed and directed the project requirements and submission materials.
