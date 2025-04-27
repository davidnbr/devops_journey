# 2. Version Control with Git

## Git Internals
- **Objects Model**:
  - Blobs: File contents
  - Trees: Directory listings
  - Commits: Snapshots with metadata
  - Tags: Named references
- **References**:
  - Branches: Pointers to commits
  - HEAD: Pointer to current branch/commit
  - Remote references
- **Storage Mechanism**:
  - `.git` directory structure
  - Objects database
  - Pack files

## Advanced Git Commands
- **Rewriting History**:
  ```bash
  # Interactive rebase
  git rebase -i HEAD~5
  
  # Squash commits
  git reset --soft HEAD~3 && git commit
  
  # Change author information
  git commit --amend --author="Name <email>"
  
  # Filter branch (complex history rewriting)
  git filter-branch --tree-filter 'rm -f passwords.txt' HEAD
  ```
- **Searching and Blame**:
  ```bash
  # Advanced log filtering
  git log --grep="bug fix" --author="John" --since="2 weeks ago"
  
  # Show changes to a specific function
  git log -L :function_name:file.py
  
  # Find when a line was introduced
  git blame -L 10,20 file.py
  
  # Binary search for bugs
  git bisect start
  git bisect bad
  git bisect good v1.0
  ```
- **Patch Management**:
  ```bash
  # Create patch
  git format-patch master..feature-branch
  
  # Apply patch
  git apply patch_file.patch
  
  # Apply patch with author information
  git am patch_file.patch
  ```
- **Submodules & Subtrees**:
  ```bash
  # Add submodule
  git submodule add https://github.com/user/repo path/to/submodule
  
  # Update submodules
  git submodule update --init --recursive
  
  # Add subtree
  git subtree add --prefix=path/to/subtree https://github.com/user/repo master --squash
  
  # Update subtree
  git subtree pull --prefix=path/to/subtree https://github.com/user/repo master --squash
  ```
- **Reflog**:
  ```bash
  # View reflog
  git reflog
  
  # Recover deleted branch
  git checkout -b recovered-branch HEAD@{1}
  
  # Recover after hard reset
  git reset --hard HEAD@{1}
  ```

## Git Branching Strategies
- **Feature Branch Workflow**:
  - Main branch remains stable
  - Features developed in isolated branches
  - PRs for code review
  - Branch → Code → PR → Review → Merge
- **Gitflow Workflow**:
  - `master`: Production releases
  - `develop`: Integration branch
  - `feature/*`: New features
  - `release/*`: Release preparation
  - `hotfix/*`: Production fixes
  - Complex but structured approach
- **Trunk-Based Development**:
  - Small, frequent commits to main branch
  - Heavy use of feature flags
  - CI/CD focused
  - Emphasis on automated testing
- **GitHub Flow**:
  - Simplified Gitflow
  - Branch → Code → PR → Review → Merge → Deploy
  - Works well with continuous delivery
- **GitLab Flow**:
  - Environment branches (`production`, `staging`)
  - Feature branches merge to main
  - Main merges to environment branches

## Git Hooks
- **Client-Side Hooks**:
  - `pre-commit`: Check code before committing
  - `prepare-commit-msg`: Modify commit message
  - `commit-msg`: Validate commit message
  - `post-commit`: Notification after commit
  - `pre-push`: Check before pushing
- **Server-Side Hooks**:
  - `pre-receive`: Validate pushes
  - `update`: Check individual refs
  - `post-receive`: Notification after receive
- **Sample pre-commit Hook**:
  ```bash
  #!/bin/sh
  # .git/hooks/pre-commit
  
  # Check for syntax errors in Python files
  for file in $(git diff --cached --name-only | grep -E '\.py$')
  do
    if ! python -m py_compile "$file"; then
      echo "Syntax error in $file"
      exit 1
    fi
  done
  
  # Run linting
  if ! pylint $(git diff --cached --name-only | grep -E '\.py$'); then
    echo "Linting issues found"
    exit 1
  fi
  
  exit 0
  ```

## Git in CI/CD Pipelines
- **Integration with CI Tools**:
  - GitHub Actions trigger on push/PR
  - GitLab CI integration with merge requests
  - Jenkins pipeline with Git triggers
- **Automated Testing**:
  - Run tests on each commit/PR
  - Report results back to Git provider
  - Block merges for failing tests
- **Deployment Automation**:
  - Deploy from specific branches
  - Tag-triggered deployments
  - GitOps approaches

## Advanced Git Workflows
- **Monorepo Management**:
  - Handling large repositories
  - Partial clones and sparse checkouts
  - Using Git LFS for binary files
- **Code Review Practices**:
  - PR templates
  - Review automation
  - Code owners
- **Release Management**:
  - Semantic versioning
  - Tag management
  - Release notes generation

## Security Best Practices
- **Sensitive Data Protection**:
  - Prevent committing secrets
  - Tools like Git-secrets
  - History cleaning for accidentally committed secrets
- **GPG Signing**:
  ```bash
  # Configure signing
  git config --global user.signingkey YOUR_GPG_KEY_ID
  git config --global commit.gpgsign true
  
  # Sign commits
  git commit -S -m "Signed commit message"
  
  # Sign tags
  git tag -s v1.0.0 -m "Signed tag"
  
  # Verify signatures
  git verify-commit HEAD
  git verify-tag v1.0.0
  ```
- **Access Control**:
  - Branch protection rules
  - Required reviews
  - Status checks
  - Protected tags

## Git Performance Optimization
- **Repository Maintenance**:
  ```bash
  # Garbage collection
  git gc
  
  # Prune unreachable objects
  git prune
  
  # Optimize local repository
  git gc --aggressive
  
  # Clean up old branches
  git remote prune origin
  ```
- **Large Repository Handling**:
  ```bash
  # Shallow clone
  git clone --depth=1 repository-url
  
  # Sparse checkout
  git clone --filter=blob:none repository-url
  git sparse-checkout set directory1 directory2
  
  # Git LFS setup
  git lfs install
  git lfs track "*.psd"
  ```

## Advanced Resources
- [Pro Git Book](https://git-scm.com/book/en/v2)
- [Git Internals PDF](https://github.com/pluralsight/git-internals-pdf)
- [Atlassian Git Tutorials](https://www.atlassian.com/git/tutorials)
- [Git Best Practices](https://sethrobertson.github.io/GitBestPractices/)
