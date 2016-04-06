# DataONE
A Drupal module that provides a stub for implementing the DataONE Member Node API.

- benefits: https://www.dataone.org/benefits-becoming-member-node
- requirements: https://www.dataone.org/member_node_requirements
- process: https://www.dataone.org/member-node-deployment-process

## Progress

Beta release for testing available at: https://github.com/Scienceondrupal/dataone/releases/tag/7.x-1.0-beta1

**Status: Testing**

Currently, we are testing the DataONE Member Node API Tier 1 implementation. There is one upcoming DataONE Member Node using the module at: https://test-prod.bco-dmo.org/d1/mn/v1

**TO DO**

1. Update the dataone_example module

If you are interested in participating in this work, please contact Adam Shepherd, Co-chair of the ESIP Drupal Working Group, at ashepherd@whoi.edu

---

Git Branching Methodology: Git Flow (http://danielkummer.github.io/git-flow-cheatsheet/)
**master**           production releases
**develop**          code in pipeline for the next release
**release-[name]**   code in pipeline for production (merges into master)
**feature-[name]**   a new feature (merges into develop)
**hotfix-[name]**    bug fixes to production (merges into develop & master)

