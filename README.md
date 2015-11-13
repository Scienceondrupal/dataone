# DataONE
A Drupal module that provides a stub for implementing the DataONE Member Node API.

- benefits: https://www.dataone.org/benefits-becoming-member-node  
- requirements: https://www.dataone.org/member_node_requirements  
- process: https://www.dataone.org/member-node-deployment-process   

## Progress

**Status: Testing**

Currently, we are testing the DataONE Member Node API Tier 1 implementation.

** TO DO **

# Provide a way for Member Node to supply its X.509 Certificate.
# Provide a way for the Drupal site to update its record at DataONE
# Provide some improved documentation on GitHub how to implementation works.
# Provide documentation about Data Packages (OAI-ORE resource maps, data, and metadata)

If you are interested in participating in this work, please contact Adam Shepherd, Co-chair of the ESIP Drupal Working Group, at ashepherd@whoi.edu

---

Git Branching Methodology: Git Flow (http://danielkummer.github.io/git-flow-cheatsheet/)  
**master**           production releases  
**develop**          code in pipeline for the next release  
**release-[name]**   code in pipeline for production (merges into master)  
**feature-[name]**   a new feature (merges into develop)  
**hotfix-[name]**    bug fixes to production (merges into develop & master)  

