# eMudhra-untrusted-certificates

Script to remove untrusted root certificates from software installations created with [EasyBuild](https://easybuild.io).

May also be useful to people not using EasyBuild as well.

## License

GPLv2

## Usage

Only tested on Linux (RHEL-based), several assumptions are made.

```shell
./remove-untrusted-root-certificates-from-EasyBuild-software-installations.sh <path> <option>
```

Supported options are:
- `--help`: print help info
- `--scan`: only scan files using known locations for untrusted root certificates, make no changes;
- `--scan-full`: scan `*.pem` and `*.crt` files (search using `find`) for untrusted root certificates, make no changes;
- `--remove`: remove untrusted root certificates from files using known locations;
- `--remove-full`: remove untrusted root certificates from `*.pem` and `*.crt` files (search using `find`);

## Logging

A log file named `remove-untrusted-root-certificates-from-EasyBuild-software-installations.log.<random_stuff>` is created on every run, in the current working directory.

## Guarantees

No guarantees whatsoever.

Well, there is one guarantee: the known paths used by the script are *definitely* **incomplete**,
and so is only looking at `*.pem` and `*.crt` files (see `--*-full` options).

Run this script at your own risk.

Make sure you understand what it does (and doesn't do) before you run it.

We are not liable for any damages, hurt feelings, or broken dreams caused by running this script.

## Use of LLMs

This script was *not* written by an LLM, although LLMs were queried for help with bash syntax shenanigans while writing it.

It was developed in a private repository by multiple EasyBuild maintainers in collaboration,
using a two-pairs-of-eyes principle (changes implemented by person A were reviewed by at least
one other person before applying them).

## What about fixing EasyBuild itself?

We are working hard on updating our [easyconfigs](https://github.com/easybuilders/easybuild-easyconfigs) to mitigate this hot mess as best we can.

For now, this brute force script should help (a bit).

We didn't cause this whole clusterfuck, but we're doing what we can to mitigate it.

More news soon (most likely an EasyBuild v5.4.2 bugfix release)...

## Feedback

All feedback welcome via https://github.com/easybuilders/eMudhra-untrusted-certificates/issues

Please be nice.

## Contributions

Patches welcome via https://github.com/easybuilders/eMudhra-untrusted-certificates/pulls

If you use any LLMs, take into account the [EasyBuild AI policy](https://docs.easybuild.io/policies/ai/).

## History

- 28 Oct 2026: list of known path patterns was expanded significantly (see PRs [#2](https://github.com/easybuilders/eMudhra-untrusted-certificates/pull/2), [#4](https://github.com/easybuilders/eMudhra-untrusted-certificates/pull/4))
- 23 Oct 2026: first (public) version

## Useful links

- https://emudhra.we-have-a-problem.com
- https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
- https://access.redhat.com/security/vulnerabilities/RHSB-2026-012
- https://nesbitt.io/2026/10/21/trust-stores-are-dependencies-too.html
- https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
- https://www.theregister.com/security/2026/10/20/indian-certification-authority-emudhras-private-keys-compromised-one-of-them-was-the-number-4/5304312
- https://social.treehouse.systems/@mgorny/117476539516487756

## What's with the passive aggressive tone of this README?!

We're *pissed*. And you should be too.

We are *this* close to starting a :goat: farm.

![](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExaGcyM2M2NTcxc3lxZnRlcXlxZWw2ajd2eGV3czNuaXl3ZXhmc25neiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/3t7RAFhu75Wwg/giphy.gif)
