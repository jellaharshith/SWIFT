# SWIFT v8.0 -- root

Production codebase: `/Users/harshithjella/SWIFT/swift/`.
Bug-bounty engagement state (screenshots, captured creds, target configs):
`/Users/harshithjella/Downloads/SWIFT/` -- do NOT commit those into `/SWIFT/`.

Full architecture lives in `swift/CLAUDE.md` (read that, not this file).

## Skill routing (gstack / superpowers / caveman shortcuts)

When the user's request matches an available skill, invoke it via the Skill tool.

- Product ideas / brainstorming    -> `/office-hours`
- Strategy / scope                  -> `/plan-ceo-review`
- Architecture                      -> `/plan-eng-review`
- Design system / plan review       -> `/design-consultation` or `/plan-design-review`
- Full review pipeline              -> `/autoplan`
- Bugs / errors                     -> `/investigate`
- QA / testing site behavior        -> `/qa` or `/qa-only`
- Code review / diff check          -> `/review`
- Visual polish                     -> `/design-review`
- Ship / deploy / PR                -> `/ship` or `/land-and-deploy`
- Save / resume context             -> `/context-save` / `/context-restore`
