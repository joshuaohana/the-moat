# Contributing to The Moat

Thanks for helping secure AI agents! 🏰

## Pattern Rules

The most impactful contribution is new detection patterns. These are the "antivirus signatures" that catch prompt injection and other attacks.

### Adding a Pattern

1. Fork the repo
2. Add your pattern to the appropriate file in `rules/`
3. Include at least one test payload in `tests/payloads/`
4. Open a PR with:
   - What the pattern catches
   - A real-world example (or realistic synthetic one)
   - Why existing patterns don't already catch it

### Pattern Format

```json
{
  "id": "INJ-001",
  "name": "ignore-previous-instructions",
  "category": "injection",
  "severity": "high",
  "pattern": "ignore\\s+(all\\s+)?previous\\s+instructions",
  "flags": "IGNORECASE",
  "description": "Classic prompt injection attempting to override system prompt",
  "references": ["https://example.com/attack-writeup"],
  "false_positive_notes": "May trigger on legitimate security research content"
}
```

### Categories

- `injection` — prompt injection / jailbreak attempts
- `hidden` — invisible text, zero-width characters, encoding tricks
- `credential` — credential patterns that shouldn't appear in external content
- `exfiltration` — patterns indicating data theft attempts
- `steering` — subtle behavioral manipulation (role-play, persona switching)

## Code Contributions

1. Fork & branch from `main`
2. Follow existing code style
3. Add tests for new functionality
4. Keep dependencies minimal (this is a security tool — small surface area matters)
5. Open a PR — all changes require review

## Reporting Vulnerabilities

If you find a security issue in The Moat itself, **do not open a public issue**. Email security@ohanaindustries.com instead.

## Code of Conduct

Be decent. We're all here to make AI agents safer.
