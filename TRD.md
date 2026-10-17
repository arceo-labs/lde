## Technical Requirements Document (TRD): Minimal-Context Dependency Indexing Pipeline

### 1. Executive Summary

**Objective:** Index all direct and transitive dependencies across the GitHub organization without cloning any repository.
**Method:** Fetch each repository's SBOM from GitHub's Dependency Graph API, convert it from SPDX 2.3 to CycloneDX 1.4, and push it to OWASP Dependency-Track for querying.

### 2. System Architecture Components

* **Component A: The Fetcher (`backend/github_client.py`, `backend/github_sbom.py`)**
* Authenticates with the GitHub API using a fine-grained PAT.
* Lists the repositories in each target org and resolves each repo's branch.
* Downloads the SPDX 2.3 SBOM from `GET /repos/{org}/{repo}/dependency-graph/sbom`.

* **Component B: The Converter (`backend/github_sbom.py`)**
* Converts SPDX packages with a purl into CycloneDX components.
* Converts SPDX `DEPENDS_ON` relationships into the CycloneDX `dependencies` graph.
* Places the repo itself in `metadata.component` so Dependency-Track can anchor the graph.

* **Component C: The Database & UI (OWASP Dependency-Track)**
* Ingests the CycloneDX SBOMs via REST API.
* Serves cross-repo component search for Package Search.

### 3. Functional Requirements

1. **No cloning:** All dependency data comes from GitHub's Dependency Graph API. No repository content is downloaded.
2. **Graph-disabled repos:** A repo with the Dependency Graph disabled returns HTTP 404. Mark it `skipped` and continue the run.
3. **Branch selection:** GitHub exports an SBOM for the default branch only. For a run-level branch override, apply the dependency-review diff (`default...branch`) to the default-branch SBOM. The result is approximate.
4. **Overwrite protection:** Refuse to replace an existing Dependency-Track project with an empty BOM, so a failed fetch never erases good data.

### 4. Technical Implementation Plan

#### Phase 1: Fetch

For each repo in the target orgs, resolve the branch and fetch the SPDX SBOM (or the default-branch SBOM plus the branch diff).

#### Phase 2: Convert

Convert the SPDX document to CycloneDX 1.4 and write it to the run directory as `{org}__{repo}.github_sbom.json`.

#### Phase 3: Ingestion to Dependency-Track

Push the CycloneDX file to the `POST /api/v1/bom` endpoint on Dependency-Track, one project per `{org}/{repo}@{branch}`.

### 5. Critical Risks & Mitigations

| Risk | Impact | Mitigation Strategy |
| --- | --- | --- |
| **Dependency Graph disabled** | Medium | Mark the repo `skipped` and report it. Coverage depends on the org enabling the Dependency Graph. |
| **Lost data on a bad fetch** | High | The empty-BOM guard refuses to overwrite an existing project with an empty BOM. |
| **Approximate branch SBOMs** | Medium | Non-default branches are built from a diff against the default branch. Treat them as approximate. |
| **API Rate Limiting** | Medium | Use a PAT with only Contents and Metadata read access, and keep run sizes within the authenticated rate limit. |
