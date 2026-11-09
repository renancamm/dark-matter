# Documentation style guide

How to write the README and the files in `docs/`. The README says what Dark Matter is, how to read a
result and how to run it. Everything else lives in `docs/`, and the README links to it.

## Voice

1. **Say what it is first.** Open with a definition: "Dark Matter is a static analyzer for…". A
   reader should know what the tool is from the first sentence, before learning why it exists or how
   it works.
2. **State, don't defend.** Describe what the tool does and stop. Don't answer objections nobody has
   raised yet ("this is not an accusation", "a determined author could…", "this does not mean…").
   If a limit matters, it goes in Limits, once.
3. **Describe capabilities, not threats.** Dark Matter is not a threat analysis. Leave out
   attackers, malware campaigns, evasion and "malicious" in user-facing docs. Say what code can reach and how
   much of it the check could follow.
4. **No analogies or marketing.** Leave out "like a recipe", "the cheapest time to…" and similar.
   A plain description is shorter and just as clear.
5. **Active voice, present tense, with a concrete subject:** "the check", "the analyzer", "the
   policy", "the mod". Write "A call into another mod counts as code that was not analyzed", not "Calls into
   other mods are considered to be unanalyzed".

## Sentences

6. **One claim per sentence.** Keep most sentences under about 25 words. Split a sentence that
   needs a semicolon and a parenthesis to hold together. Don't nest clauses: "how much of what the
   code can do it can follow" becomes "whether the check could follow all of the code".
7. **Avoid "not X, but Y" chains.** One contrast is enough to make a point. If a paragraph has
   three, cut two.
8. **Plain words.** Use "uses" rather than "makes use of" and "can't" rather than "is not able to".
   Contractions are fine.
9. **American spelling**, to match the code and commands (`analyze`, `behavior`, `defense`).

## Structure

10. **Say each thing once.** Every idea has one home. Elsewhere, link to it. "What the code can do,
    not what it does" lives in the README's Design principles. Don't repeat it under Tiers, The scan
    and Limits.
11. **The README is the summary, and `docs/` holds the detail.** The README leaves out policy
    version numbers, IL opcodes, namespaces and edge cases, apart from one short example where a
    reader needs it. If a README paragraph needs a footnote, move the detail to `docs/` and link it.
    The README's opening sections (principles, tiers) are an overview: one line per item, a few
    examples rather than full lists.
12. **Tables for parallel facts, lists for three or more items, prose for reasoning.** Don't put a
    paragraph under a table to explain the table. Put the meaning in a column.
13. **Headings are short noun phrases in sentence case:** "Tiers and labels", "Quick start". Give
    each section one job.

## Terms

14. **Use the product's words exactly, and always the same way:**

    | Term | Use for | Don't write |
    |---|---|---|
    | **No code**, **Limited access**, **Broad access** | the three tiers | "safe", "dangerous", "Full access" |
    | group (**Deep game access**, **System access**, **Couldn't be fully checked**) | why a mod is Broad access | "severity", "level" |
    | label | one thing the code can reach, in the policy's wording | "permission", "flag" |
    | the check, the analyzer | `darkmatter` and what it decides | "the scanner", "the engine" |
    | the pipeline | `darkmatter-pipeline` | |
    | the policy | `policy/policy.jsonc` | "the rules file", "the config" |
    | the game map | the game-API map made from the player's copy of the game | "the game profile" in prose |
    | default deny | the rule that whatever can't be followed or isn't expected is Broad access | "whitelist" |

15. **Quote player-facing text exactly as the policy has it.** Tier and group summaries ("Short
    description") and label names come from `policy/policy.jsonc`. When the policy changes them, the
    docs change in the same commit.

## Formatting

16. **Bold** marks a term the text defines, or a bullet's lead-in phrase. Don't use it for emphasis
    in running text.
17. **Code formatting** is for identifiers, commands, file names and policy keys: `Process.Start`,
    `scan`, `policy.jsonc`. Product names (Dark Matter, Harmony, KSA) are plain text.
18. Wrap prose at 100 columns. Tables and diagrams are exempt.
19. Diagrams are plain-text blocks that read without rendering. Keep them in the README only when
    they show something the prose doesn't.

## Accuracy

20. **Every claim must be true at the current policy version.** A change that can alter a result
    updates the docs it affects in the same commit, as well as `docs/policy-changelog.md`.
21. **Link, don't paraphrase, the criteria.** The complete criteria are in
    [tiers-and-labels.md](tiers-and-labels.md). A summary elsewhere must not contradict it.

## Before committing a docs change

- Does the first sentence of each section say what the section is about?
- Is any sentence there only to head off an objection? Cut it.
- Does an idea appear twice? Keep one copy and link to it.
- Do the tier, group and label names match the policy exactly?
- Run `scripts/format.sh --whitespace`.
