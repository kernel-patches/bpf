const fs = require('fs');

// The review prompts wrap text at 78 columns; tldr.md asks for at most 40 words.
const TLDR_WIDTH = 78;
const TLDR_MAX_WORDS = 60;

function wrap(text, indent) {
  const lines = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (line && line.length + 1 + word.length > TLDR_WIDTH) {
      lines.push(line);
      line = indent + word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  lines.push(line);
  return lines.join('\n');
}

function readTldr(file) {
  if (!file || !fs.existsSync(file))
    return null;
  const tldr = fs.readFileSync(file, 'utf8').trim();
  if (!tldr.startsWith('TL;DR') || tldr.split(/\s+/).length > TLDR_MAX_WORDS) {
    console.log(`Ignoring ${file}: not a valid TL;DR`);
    return null;
  }
  // "- " starts an item; any other line continues the one before it.
  const paragraphs = [];
  for (const line of tldr.split('\n').map(l => l.trim()).filter(Boolean)) {
    if (line.startsWith('- ') || !paragraphs.length)
      paragraphs.push(line);
    else
      paragraphs[paragraphs.length - 1] += ` ${line}`;
  }
  return paragraphs.map(p => wrap(p, p.startsWith('- ') ? '  ' : '')).join('\n');
}

module.exports = async ({github, context}) => {
  const jobSummaryUrl = `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`;
  let reviewContent = fs.readFileSync(process.env.REVIEW_FILE, 'utf8');
  const subject = process.env.PATCH_SUBJECT || 'Could not determine patch subject';
  const tldr = readTldr(process.env.TLDR_FILE);
  if (tldr) {
    // KPD emails the comment from its first quoted line on.
    const at = Math.max(reviewContent.search(/^>\s*\S.*$/m), 0);
    reviewContent = reviewContent.slice(0, at) + `> ${subject}\n\n${tldr}\n\n` + reviewContent.slice(at);
  }
  const commentBody = `
\`\`\`
${reviewContent}
\`\`\`

---
AI reviewed your patch. Please fix the bug or email reply why it's not a bug.
See: https://github.com/kernel-patches/vmtest/blob/master/ci/claude/README.md

In-Reply-To-Subject: \`${subject}\`
CI run summary: ${jobSummaryUrl}`;

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
