# AI policy

This project follows the [LLVM AI Tool Use Policy](https://llvm.org/docs/AIToolPolicy.html).  The basic idea is that:

```
You, as a human, are the code author and responsible for all code submitted to and interations with the project
```

This means:

* Contributors must read and review all LLM-generated code or text before they
  ask other project members to review it.
* Contributors are expected to be transparent and label contributions that
  contain substantial amounts of tool-generated content/
* Pull requests that have been assisted by AI should include an `Assisted-by:`
  trailer in the commit message.
* With the exception of language translation, all interaction with the projects
  should be in the contributors own words.
* Agents that take action in our digital spaces without human approval, such as
  the GitHub @claude agent, are banned.


## How this fork applies the trailer

Commits in this fork that were written with LLM assistance carry a trailer
naming the tool:

```
Assisted-by: Claude Code
```

Add it to the commit itself, e.g. `git commit --trailer "Assisted-by: <tool>"`,
so the signal survives rebases and cherry-picks if the change is sent upstream.

The trailer is a statement of fact about how a commit was written, not a
checkbox: commits written without AI assistance carry nothing extra.  That is
also why there is no commit hook or CI check for it -- neither can tell whether
a tool was used, so either would only produce false failures.


---

This document contains excerpts from the LLVM AI Tool Use Policy licensed under
the Apache License v2.0 with LLVM Exceptions and are Copyright © 2003-2026,
LLVM Project.
