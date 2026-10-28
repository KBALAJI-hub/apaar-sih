# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- AICTE regulators monitor national enrollment and institutional compliance.
- Institution registrars manage student enrollment records and resolve validation issues.
- Verifiers check academic credentials.
- Students manage consent for credential disclosure.

## Product Purpose

ApaarAnvaya is a privacy-aware academic records and credential verification platform for AICTE and participating institutions. It helps regulators identify intake violations and duplicate or concurrent enrollment, while enabling credential checks that respect student consent.

## Positioning

The platform connects institution-submitted student records with intake guardrails, explainable validation and anomaly flags, consent-tiered verification, and cryptographically verifiable records with a tamper-evident audit trail.

## Operating Context

The project is an SIH demonstration prototype for AICTE Problem Statement 26263. Its workflows serve four roles: AICTE regulator, institution registrar, verifier, and student. The local demo uses pre-seeded accounts and data; registry lookup and OTP flows are simulated.

## Capabilities and Constraints

- Validates APAAR ID format and student records.
- Checks approved intake and surfaces duplicate enrollment and other validation issues.
- Presents institution and regulator dashboards, reports, and anomaly information.
- Supports credential verification with student consent tiers.
- Implements signed records and a hash-chained audit trail.
- Uses role-based access for its four user roles.
- The existing application is a FastAPI and SQLModel web app with Jinja templates, Tailwind CSS via CDN, and Chart.js.
- The registry and OTP integrations are demo simulations, not live external integrations.
- Preserve the established APAAR and AICTE terminology.

## Brand Commitments

- Product name: ApaarAnvaya.
- Retain APAAR and AICTE terminology where it describes the registry, regulator, or problem domain.

## Evidence on Hand

- The repository includes an SIH project description, implementation documentation, demo credentials, and a guided demo walkthrough in [README.md](./README.md).
- The README describes a canonical dataset snapshot of 13,089 institutions, 58,297 programs, and 120 signed students.
- The repository contains API, validation, cryptographic-signature, consent, and audit-chain implementations, plus an integration checklist.
- Registry and OTP behavior is simulated in the demo. No customer testimonials, production deployment evidence, or formal accessibility conformance evidence was identified.

## Product Principles

- Protect student privacy through consent-controlled disclosure.
- Make enrollment and compliance issues actionable for institutions and regulators.
- Make credential integrity and validation outcomes verifiable.
- Keep each role focused on the records and decisions relevant to its responsibilities.
