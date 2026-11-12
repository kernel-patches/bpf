# AI Code Reviews in BPF CI

## TL;DR
- **Please make sure AI is actually wrong before dismissing the review**
  - An email response explaining why AI is wrong would be very helpful
- BPF CI includes [a workflow](https://github.com/kernel-patches/vmtest/blob/master/.github/workflows/ai-code-review.yml) running AI code review
- The reviews are posted as comments on [kernel-patches/bpf PRs](https://github.com/kernel-patches/bpf/pulls)
- The review comments are forwarded to the patch recipients via email by [KPD](https://github.com/kernel-patches/kernel-patches-daemon)
- Prompts are here: https://github.com/masoncl/review-prompts

If you received an AI review for your patch submission, please try to evaluate it in the same way you would if it was written by a person, and respond.
Your response is for humans, not for AI.

## How does it work?

BPF CI is processing every patch series submitted to the [Linux Kernel BPF mailing list](https://lore.kernel.org/bpf/).
Against each patch the system executes various tests, such as [selftests/bpf](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf), and since recently it also executes automated code reviews performed by LLM-based AI.

BPF CI runs on [Github Actions](https://docs.github.com/en/actions) workflows orchestrated by [KPD](https://github.com/kernel-patches/kernel-patches-daemon).

The AI review is implemented with [Claude Code GitHub Action](https://github.com/anthropics/claude-code-action), which essentially installs Claude Code command-line app and a MCP server with a number of common tools available to it.

LLMs are accessed via [AWS Bedrock](https://aws.amazon.com/bedrock), the GitHub Actions workflow authenticates to AWS account with [OIDC](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).

To achieve the output that might have led you to this page, [a set of elaborate prompts](https://github.com/masoncl/review-prompts) were developed specifically targeting the Linux Kernel source code.
The workflow checks out the Linux and prompts repository and initiates the review with a trivial [trigger prompt](https://github.com/kernel-patches/vmtest/blob/master/.github/workflows/ai-code-review.yml#L91-L94).

### Are the reviews even accurate?

We make every effort for AI reviews to be high-signal messages. Although the nature of LLMs makes them prone to mistakes.

At this point this is still an experiment, but the results so far have been promising.
For example, AI is pretty good at catching dumb mistakes (e.g. use-after-free) that humans can easily miss.
At the same time AI can miss context obvious to a human, such as relationships between newer and older changes.

If you'd like to suggest an improvement to the prompts, open a PR to [review-prompts](https://github.com/masoncl/review-prompts) repository.

### Will my patch get nacked because of the AI review?

Paraphrasing IBM training manual:
> "A LLM can never be held accountable, therefore a LLM must never make an Ack/Nack decision"

The review prompts are designed such that AI is only searching for the regressions it can provide evidence for.
For the majority of patches a review is not generated, so if you received one it's worth evaluating.

It's unlikely that your patch gets discarded *just* because AI found something, especially if you address it or explain why AI is wrong.

But if you ignore an AI review, human reviewers will likely ask for a reason.

### What if I don't like it?

Bring it up with the maintainers on the mailing list and elaborate.

It is expected that AI may be mistaken. However it is also expected that the patch authors answer reasonable questions about the code changes they propose.

If there is a technical issue (say with email notifications, formatting etc.), open an issue in [this repository](https://github.com/kernel-patches/vmtest/issues).

### Who pays for the tokens?

[Meta Platforms, Inc.](https://www.meta.com/)

BPF CI in its current form has been developed and maintained by the Linux Kernel team at Meta. Most of the relevant hardware is also provided by Meta.

### Who set this up?

- [Chris Mason](https://github.com/masoncl) is the prompt engineer
- [Ihor Solodrai](https://github.com/theihor) is the infra plumber
