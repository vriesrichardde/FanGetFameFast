# General Considerations
- Concurrency is not yet fully present and might cause interference when parallel investigations are started. F3 seems to notice / repair when it occurs, but it should be handled in the architecture
- Sometimes it seems to go out of bounds and store files in different places which is not part of the design. This can lead to research files being committed to the repo and/or stray files without clear context
- You cannot assume that Claude will perform consistently. It can deviate output, and misinterpret your prompts resulting in missing important aspects of the research. It is very important to build quality gates and completeness gates, confirm that the reasoning, deep dives and pivoting cycles have taken place
- Batch operations are not working smoothly yet. They tend to leave half of the remaining work open by just not executing certain tasks. Doing a 1 by one run per host and then asking to correlate works best.
- There might still be inconsistencies between FAN/FAME/FAST. Due to time constraints not everything was aligned yet
- New features have been added, so new runs of the cases_for_judges cases might be more complete
- Validate the X86 architecture SIFT Workstation as I have not worked on an Intel based machine since creation