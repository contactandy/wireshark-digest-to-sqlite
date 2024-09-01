# wireshark-digest-to-sqlite
Create a SQLite database of the Wireshark digests from a packet capture.  

# Contributions 

For your convenience, a pre-commit configuration file is included in this
project which formats and lints. To install, follow the instructions at
[https://pre-commit.com](https://pre-commit.com/#quick-start). 

This project uses the `ruff` for formatting. A Github action automatically
applies `ruff format` on pull requests and any changes are committed on top of
the request.  If not pre-formatting before submitting a pull request, make sure
to bring back any formatting changes automatically applied to origin.
