# Repository and publication

The initial pilot source is published on `main` in `edgeworks/deepsnout`.
It contains source, dotfiles, container configuration, tests and documentation.
Generated GUI screenshots are distributed in the original source archive rather
than versioned here. No running-instance data or operational credentials belong
in the repository.

The first attempted publication was blocked because the new repository had not
been granted to the GitHub integration. After the operator updated repository
access, a LICENSE write was verified. The source publication preserves that
initial commit; it does not replace history or require a force-push.

## Checkout and updates

```sh
git clone https://github.com/edgeworks/deepsnout.git
cd deepsnout
# Later, before rebuilding; keep local operational configuration out of Git:
git pull --ff-only
```

The GitHub Actions workflow exercises SQLite/PostgreSQL tests and the container
first-run sequence. Check its run for the commit you deploy; the presence of a
workflow file is not evidence that its checks have passed. If the integration
cannot write `.github/workflows/ci.yml`, that is a separate permission boundary
from ordinary repository Contents writes, not a reason to increase the workflow's
own permissions.

For development, use a branch, run the test suite, and regenerate MANIFEST.sha256
for release snapshots. Never paste tokens into chat or commit credentials.
