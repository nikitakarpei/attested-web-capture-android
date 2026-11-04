# Security policy

Report vulnerabilities privately, not in a public issue: **Security → Report a vulnerability** on this repository,
or email nikitakarpei@mailbox.org. Include how to reproduce it.

**In scope**: this repository and its releases: the app, its build and its release signing. Flaws in the capture
format or the verifier go to [Hardware-Attested Statements](https://github.com/nikitakarpei/hardware-attested-statements/security).
**Out of scope**: Android, device vendors and the services the app relies on (FreeTSA, drand), unless the app
mishandles them.

We acknowledge reports within 7 days, assess them within 14, and aim to fix within 90, with the disclosure date
agreed with you. Fixes are announced in a GitHub security advisory (with a CVE where one applies) and the
changelog; reporters are credited unless they prefer not to be.

Only the latest release is supported.
