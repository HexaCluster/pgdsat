# How to contribute

## Before Submitting an issue

1. Upgrade to the latest version of pgdsat and see if the problem remains

2. Look at the [closed issues](https://github.com/hexacluster/pgdsat/issues?state=closed), we may have already answered a similar problem

3. [Read the doc](http://github.com/hexacluster/pgdsat/). It is short and useful.

## Keep Documentation Updated

pgdsat documentation can be obtained first with `pgdsat --help`
The file `doc/pgdsat.pod` is the description of the utilities containing global
information and usage of commands from `--help` option.

The `README.md` is generated using: `pod2markdown doc/pgdsat.pod README.md`

The man-page is generated automatically with the installation commands.
