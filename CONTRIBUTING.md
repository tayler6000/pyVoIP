# pyVoIP Contributing Guidelines

Thank you for your interest in contributing to our project! This guide should cover everything you need to know to successfully contribute to pyVoIP, but if you notice any deficiency please create a PR, or if you have a question create a discussion!

## FEATURE FREEZE WARNING

There is currently a feature freeze for pyVoIP v1.x, which is currently the master branch. Only PRs for small bug fixes and security issues will be accepted for pyVoIP v1.6 (master). No other PRs will be accepted on master.

## I Have a Question

If you have a question, please [search if an issue or discussion has already been created](https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests#search-by-the-title-body-or-comments), and don't forget to check closed! If not, create a discussion on the [discussion page](https://github.com/tayler6000/pyVoIP/discussions). Please do not create an issue for questions (unless the question is actually a feature request in disguise :wink:).

## I Have an Error or Feature Request

If you have an error or a feature request, please go to the [issues page](https://github.com/tayler6000/pyVoIP/issues) and [search if an issue has already been created](https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests#search-by-the-title-body-or-comments). If you can't find an open, or closed, issue, feel free to create one. We will use this issue to discuss possible fixes for the error, or possible implementations of the feature. We will also link future PRs to the issue. This will allow you to keep track of the progress on the issues that matter the most to you.

## How to Contribute

There are a few ways to contribute to the project. You could help with issue triage, or answering questions.  If you want to work on the repository itself, you could work on our documentation, increase our test coverage, fix bugs, or implement new features.

### Contributing Code or Documentation

If you are new to the project, please make a fork of this repository to contribute. If you have received rights to this repository, you may create a branch on the repository itself.

#### Important Things to Remember/Include

- Our goal is to have pyVoIP support the oldest version of Python that is [currently supported](https://devguide.python.org/versions/), however, we have moved ahead to Python 3.8 as it introduced many helpful features, and Python 3.7 reaches end-of-life later this year.
- PyVoIP is not completely typed yet, but it is a goal we're working towards. Including Python 3.8 / mypy compatible type signatures in your PRs is greatly appreciated.
- We are also looking to increase our test coverage, including tests for any new features added in a PR is not required, but very welcome.
- Documentation is very important to our end users. Docstrings are great, and updating `docs/` is amazing, but again, not required.

#### Branch Naming Convention

Branch naming conventions were originally discussed in issue #13. We use the following formula for branch names: `{type}/Issue-{issue number}`, `{type}/Issue-{issue number}_{second issue number}`, etc.  PRs should, ideally, only fix one issue, but exceptions are made if two issues are closely related.  Generally, an issue should always exist for a PR, but if something is a trivial change, it is acceptable to use a descriptive name instead, i.e. `docs/fix-typos`.

We currently have the following types:

| Description | Type |
| ----------- | :--: |
| Documentation Fixes / Improvements | docs |
| Feature Requests | feature |
| Bug Fixes | bugfix |
| Security Issues | security |
| Other Fixes | fix |

#### Code Style

Code style was originally discussed in issue #12. The code style for pyVoIP v1.x was almost exactly `not PEP8`, but in the name of uniformity, pyVoIP is migrating to [PEP8](https://peps.python.org/pep-0008/) conventions. This is why there is currently a feature freeze for pyVoIP v1.x, pyVoIP v2.0.0 is a major refactor and a breaking change. If you see anything that violates our code style in `development` feel free to create a PR to fix it.

We have the following code style rules:

- Global variables will use the `UPPER_CASE_WITH_UNDERSCORES` style.
- Use `_private_thing` for functions or variables that should not be accessed by another class.
- Use `__hidden_thing` for functions or variables that should not be accessed by another class or subclasses.
- When PEP8, Flake8, and Black are in disagreement, Black prevails, then Flake8, and lastly PEP8.
- File line endings MUST be in UNIX format.
- Anything else is fair game.

#### Commit Message Style

Commit messages should always follow the same format.  We have provided the following template below. Obviously, only the relevant fields are required for your message.

Format:

```
Release pyVoIP v{major}.{minor}.{patch}

{linking keyword} #{issue number}

[{change type}] Description of change
[{change type}] Description of change 2

Co-authored-by: {username} <{email}>
```

You can find a list of linking keywords [here](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/using-keywords-in-issues-and-pull-requests).  It is okay to have a linking keyword in the actual line instead of at the top, i.e. `[FIX] Did the thing. Fixed #18`

The following table shows all the change types we use. All like change types should be listed together, in the order listed in the table.

| Description | Type |
| ----------- | :--: |
| Added feature, docs, etc. | ADD |
| Changed existing feature, doc, etc. | CHANGE |
| Fixed something that was broken | FIX |
| Removed code, file, etc. | REMOVE |

Each line of your commit message should not exceed 79 characters.  PEP8 limits code to 79 characters long because `Limiting the required editor window width makes it possible to have several files open side by side, and works well when using code review tools that present the two versions in adjacent columns`. This will ensure readability when running `git log`.

For multilined descriptions, the following line should start inline with the first letter after the change type.

##### Some Examples

```
[ADD] Added ports to SIP messages where previously excluded.
[ADD] Added To/From/Contact dictionary type to pyVoIP/types.
[ADD] Added __get_tfc_header to SIP/client.
[ADD] Added `to` attribute to SIP requests to get the addr from the top line,
      it is populated with __get_tfc_header.
[ADD] Added int casting attempt to Via header attributes.
[ADD] Added lots of docstrings to pyVoIP/sock.
[ADD] Added functionality to VoIPConnection and VoIPSocket.
[ADD] Added 7 new tests for SIP request `to` attribute.
[ADD] Added 5 new Via header tests.
[CHANGE] Changed pytest workflow to expose port 5061 on dockerfile.
[CHANGE] Changed docker start.bat to expose port 5061.
[CHANGE] Removed recvLock.
[CHANGE] Migrated from socket.socket to VoIPSocket.  (Currently only register
         and deregister migrated)
[CHANGE] Changed heading attribute in SIP messages from bytes to list[str].
[CHANGE] Changed SIP message summary to use raw heading.
[CHANGE] Changed SIP header parsing for To/From/Contact to use
         __get_tfc_header.
[FIX] Fixed TCP registration tests.
[REMOVE] Removed self.out from SIP/client.py
[REMOVE] Temporarily removed timeouts from register and deregister. The
         previous method would catch keyboard interrupts causing a bad
         debugging experience. It is also likely incompatible with VoIPSocket.
```

```
[ADD] Added TLS support. Closes #54
[ADD] Added TLS tests.
[ADD] Added TLS options in pyVoIP/__init__.py, namely set_tls_security
```

```
Fixed #27
Fixed #38

[ADD] Added NoPortsAvailableError in VoIP
[ADD] Added VoIPPhone.request_port(blocking=True).
      If blocking is set to false, NoPortsAvailableError may be raised,
      otherwise will wait.
[ADD] Added VoIPPhone.release_ports(call: Optional[VoIPCall] = None).
      If call is provided, release ports assigned to call,
      Otherwise release all ports not in use.
[ADD] Added VoIPPhone._cleanup_dead_calls(). It handles dead threads.
[CHANGE] Changed VoIPCall to not take portRange. It is now pulled from VoIPPhone
[CHANGE] Changed all instances of port assignment to VoIPPhone.request_port()
[CHANGE] Changed VoIPPhone.start() to except BaseException instead of Exception
[CHANGE] Changed docs to reflect changes.
[FIX] Fixed improper error raise in SIPClient.start()
[FIX] Fixed infinite loop not stopping on shutdown in SIPClient.genTag()
```

```
Release pyVoIP v1.6.4

Fixed #74

[FIX] Fixed gen_register always generating a new Call-ID, which broke some PBXs that required auth.

Co-authored-by: hartwigt <53487604+hartwigt@users.noreply.github.com>
```

### PRs, Approval, and Merging

PRs may be submitted by anyone, approved by at least one contributor who has the rights, and must be merged by the code owner, @tayler6000.  PRs made by the code owner may be merged by anyone who's review was requested by the code owner for that PR, after it is approved of course.


## Current Goals

There are three current goals for pyVoIP 2.0.0:

1. Go over the entire library and ensure it follows RFC 3261 and others.
2. Refactor everything to be compliant with our code style / PEP8.
3. Fix type annotations.

These goals are overarching, they do not include goals for features and improvements.

If you've gotten this far, thank you so much! We really appreciate you taking the time to read all these guidelines, and look forward to future contributions!
