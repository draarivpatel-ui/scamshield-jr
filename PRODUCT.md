# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

delegated: static HTML, CSS and JavaScript with a shared Node-compatible rule engine. The contest brief requires an offline prototype with zero dependencies, so no framework or runtime package is introduced.

## Users

A middle or high school student helping a grandparent decide what to do with a suspicious text message, email or direct message at home.

## Product Purpose

ScamShield Jr turns a confusing message into specific evidence a family can discuss. It highlights exact phrases and header details that match common scam tactics, explains why each tactic works, and gives a short read-aloud script for the next safe step.

## Positioning

The product is an offline teaching analyzer, not a verdict machine. It never declares a message safe. It names residual risk and the two things it cannot evaluate, so families practice verification instead of outsourcing judgment.

## Operating Context

The prototype runs locally in a browser, uses only pasted synthetic messages, makes no network calls, and includes a six-message practice drill. The contest audience evaluates the working prototype, tests, documentation, screenshots and a narrated demonstration video.

## Capabilities and Constraints

- Deterministic detectors cover urgency pressure, payment-rail switching, sender-domain mismatch, lookalike domain characters, reply-to divergence, attachment type, credential-request phrasing and family emergency scripts.
- Every positive detector returns exact source spans so the interface can highlight evidence.
- The engine cannot inspect live links, follow redirects, authenticate a sender or confirm whether an account was compromised.
- All examples are synthetic and use reserved domains or fictional accounts.
- The prototype must run on Node 22 or newer for tests and in a modern browser without a build step.

## Brand Commitments

The name is ScamShield Jr. The voice is calm, direct and family-friendly. It must avoid fear theater and must never use the word "safe" as a final verdict.

## Evidence on Hand

No real scam messages are used. All demonstrations are authored synthetic fixtures inside the repository.

## Product Principles

1. Evidence before judgment.
2. Teach the tactic, not just the answer.
3. Verification beats certainty.
4. Offline by default.
5. Practice should feel manageable for a student.

## Accessibility & Inclusion

The interface must be keyboard operable, readable at a laptop size, high contrast, and understandable without security jargon.
