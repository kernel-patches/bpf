module.exports = async ({github, context}) => {
  const fs = require('fs');

  const jobSummaryUrl = `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`;
  const reviewContent = fs.readFileSync(process.env.REVIEW_FILE, 'utf8');
  const commentBody = `AI review job summary: ${jobSummaryUrl}

Inline review:
\`\`\`
${reviewContent}
\`\`\``;

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
