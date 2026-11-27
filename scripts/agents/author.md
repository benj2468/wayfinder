# Authoring modes (every role that writes code)

Your role file says what your lane is, where your tasks come from, and your
domain's rules. This file says how a run goes. The orchestrator's task message
tells you which mode this run is in, and your branch prefix
(`agent/<role>/`). Create every branch from `origin/main` with that prefix:
the prefix is how the orchestrator recognises your PRs.

## `respond <PR>`

The principal engineer, Ben, or both have reviewed your PR.

1. Check out the PR branch. Read the latest `🤖 **principal-engineer**` review
   and every unsigned (Ben) comment newer than your last reply.
2. Address each point. Either fix it with a commit, or explain in a reply why
   you disagree. Ben's comments are never optional.
3. If the review was a restart (`next=restart`), it is a brief for a new
   cycle: follow it, even where that means redoing work that was accepted.
4. Re-run the tests you touched and `nix fmt`, then push.
5. Post **one** PR comment listing each point and what you did about it.
6. Finish with `RESULT: updated #<n>`.

Stay inside the PR's scope. A good idea that the review raised but that does
not belong in this PR goes in your log's **Next** line, not in this branch.

## `notes <PR> final=<yes|no>`

The principal approved your PR but left non-blocking notes. The orchestrator
runs you straight after the approval, so the notes are dealt with in the same
cycle. Check out the branch and decide one of these for each note:

- **Fix it in this PR**, if it is small and in scope. Then push. With
  `final=yes` this was the last review round, so do not push: file an issue or
  decline instead.
- **File an issue**, if it is real work outside this PR. Always file one when
  the note reports a suspected bug or a surprising measurement. Labels are not
  yours to set, so name the area in the title, for example `fix(routing): …`
  or `feat(sim): …`.
- **Decline it**, with a one-line reason. "No action needed" from the
  principal is a fine reason to decline.

Post **one** PR comment saying what you did with each note. Finish with
`RESULT: updated #<n>` if you pushed, otherwise `RESULT: noop`.

## `work`

1. **Feedback first.** If any of your open PRs has an unsigned (Ben) comment
   you have not answered, handle the oldest one exactly as in `respond` mode,
   then stop.
2. **WIP limit.** If the orchestrator says you are at your open-PR limit,
   start nothing new. Write a log entry and finish with `RESULT: noop`.
3. **Bugs before features** (`rules.md`). Take the most urgent open bug whose
   fix lies in your lane, including bugs you filed yourself.
4. **Otherwise, take one task** from your backlog (your role file says where
   it is). Pick the first item that no open PR already covers, and cut it to
   one PR's worth of work, meaning a reviewer can read it in about 20 minutes.
   Then:
   - Write the failing test(s) and commit them on their own.
   - Implement it, commit, and get the touched tests green.
   - Tick a roadmap item only if this PR finishes it. Ask Ben for that in the
     PR description, because `scripts/agents/` is not yours to edit.
   - Open the PR with the `mr` skill, using a Conventional Commits title.
5. Finish with `RESULT: opened #<n>`, or `RESULT: blocked …`.

A task that needs files outside your lane is not forbidden. The PR is still
reviewed, and then waits for Ben's sign-off on those files. Keep such files to
what the task strictly needs, and say in the PR description why each one is
there. Where the change is large, or touches a shared crate's behaviour, write
a design doc instead.
