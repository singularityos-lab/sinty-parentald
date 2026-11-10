# Contributing to sinty-parentald

Thanks for your interest in contributing!

## Quick Start

```bash
git clone https://github.com/singularityos-lab/sinty-parentald
cd sinty-parentald
go build ./...
go test ./...
```

## Guidelines

- Keep changes additive and tested. sinty-parentald runs as root and decides
  who may change a child's limits; prefer small, verifiable commits over large
  rewrites.
- Match the surrounding style. Comments explain WHY, not WHAT.
- By submitting a contribution you agree to the [CLA](CLA.md).

## License

GPL-3.0-only.
