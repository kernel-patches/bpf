module.exports = async ({github, context}) => {
  const fs = require('fs');

  const jobSummaryUrl = `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`;
  const reviewContent = fs.readFileSync(process.env.REVIEW_FILE, 'utf8');
  const subject = process.env.PATCH_SUBJECT || 'Could not determine patch subject';
  const commentBody = `
\`\`\`
${reviewContent}
\`\`\`

---
AI reviewed your patch. Please fix the bug or email reply why it's not a bug.
See: https://github.com/kernel-patches/vmtest/blob/master/ci/claude/README.md

In-Reply-To-Subject: \`${subject}\`
CI run summary: ${jobSummaryUrl}
`;

  await github.rest.issues.createComment({
    issue_number: context.issue.number,
    owner: context.repo.owner,
    repo: context.repo.repo,
    body: commentBody
  });

  await github.rest.issues.addLabels({
    issue_number: context.issue.number,
    owner: context.repo.owner,
    repo: context.repo.repo,
    labels: ["ai-review"],
  });
};
