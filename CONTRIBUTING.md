# Contributing

Thank you for your interest! This project is part of the Alpha Intelligence sovereign OS ecosystem.

## Quick Start

```bash
git clone https://github.com/iAAi33iAAi/safety-kernel.git
cd safety-kernel
pip install -r requirements.txt   # or follow repo-specific setup
```

## How to Contribute

| Type | How |
|------|-----|
| Bug fix | Fork then branch then fix then PR |
| New feature | Open an issue first |
| Documentation | Edit in docs/ or root .md files |
| Tests | Add to tests/ following existing patterns |

## Branching Convention

```
feature/short-description
fix/short-description
docs/short-description
```

## Commit Prefixes

| Prefix | Use for |
|--------|---------|
| feat: | New feature |
| fix: | Bug fix |
| docs: | Documentation |
| test: | Tests |
| ci: | CI/CD changes |

## Pull Request Process

1. Ensure CI passes (all tests green)
2. Update documentation if needed
3. Reference the related issue (Closes #N)
4. Request review from a maintainer

## Standards

- Type hints on all public Python functions
- Docstrings on all public classes and functions
- Tests for all new logic (aim for >90% coverage on src/)

## Questions?

Open a Discussion or tag @iAAi33iAAi in an issue.
