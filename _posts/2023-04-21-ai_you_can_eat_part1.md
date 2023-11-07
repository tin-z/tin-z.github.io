---
layout: post
title:  "AI you can eat (part 1): Git CVE-2023-23946, CVE-2022-23521, and CVE-2022-41903"
categories: [chatgpt, cve, git]
author: Altin (tin-z)


---


Some blogs ago we discussed about ChatGPT and how it can be used to ease our security researcher life when the task to be done is that to make PoC for recent CVEs.

And so we have targeted Redis, GO with CVE-2023-28425 and CVE-2023-24534 rispectevely.


This time we will go in berserk mode by trying to exploit as many target as possible. Why i do care about that? Because by doing i can learn more, and chatGPT even if it gives me wrong or incomplete information, in the meanwhile i am aquiring more knowledge about the target and in future i could use that same knowledge to do for example variant analysis and maybe to find new old vulnerabilities, and so on.


The blog series is called "AI you can eat: writing CVE PoCs with ChatGPT" and is splitted into:
 - Part 1 : Git CVE-2023-23946, CVE-2022-23521, and CVE-2022-41903 (this blog)
 - Part 2 : Chrome's blink 
 - Part 3 : `<target-3>`
 - Part 4 : `<target-4>`
 - Part 5 : `<target-5>`

Please note, i am not an exploit developer, so for me doing a simple PoC crashing chrome and explaining why it happened is enough to consider the job done. Also i have no knowledge about the codebase before posting the blog.


(da mettere alla fine) Refs:

 - previous blogs [Dissecting redis CVE-2023-28425 with chatGPT as assistant](https://tin-z.github.io/redis/cve/chatgpt/2023/04/02/redis-cve2023.html), [Lost in ChatGPT's memories: escaping ChatGPT-3.5 memory issues to write CVE PoCs](https://tin-z.github.io/chatgpt/go/cve/2023/04/14/escaping_chatgpt_memory.html)
 - [LLM Hacker's Handbook](https://doublespeak.chat/#/handbook)





----

## Start


### Git


```bash
man git | head -30

GIT(1)                                                                                     Git Manual                                                                                     GIT(1)

NAME
       git - the stupid content tracker

SYNOPSIS
       git [--version] [--help] [-C <path>] [-c <name>=<value>]
           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]
           [-p|--paginate|-P|--no-pager] [--no-replace-objects] [--bare]
           [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]
           [--super-prefix=<path>] [--config-env=<name>=<envvar>]
           <command> [<args>]

DESCRIPTION
       Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals.

       See gittutorial(7) to get started, then see giteveryday(7) for a useful minimum set of commands. The Git User’s Manual[1] has a more in-depth introduction.

       After you mastered the basic concepts, you can come back to this page to learn what commands Git offers. You can learn more about individual Git commands with "git help command".
       gitcli(7) manual page gives you an overview of the command-line command syntax.

       A formatted and hyperlinked copy of the latest Git documentation can be viewed at https://git.github.io/htmldocs/git.html or https://git-scm.com/docs.

OPTIONS
       --version
           Prints the Git suite version that the git program came from.

           This option is internally converted to git version ...  and accepts the same options as the git-version(1) command. If --help is also given, it takes precedence over --version.

       --help
```

<br />

### CVE-2022-23521 

<p align ="center">
  <img src="/files/2023-04-14/t1.jpg">
</p>

<br />

We use the same techniques explained on the previous blog. So we do git diff of the versions v2.30.6 and v2.30.7. Then we save the description of the vulnerability and also removing stuff which adds noise, here for example we could remove "remote code execution" as it does not make sense.

```bash
rm -rf repo_folder output

python downloader_with_tokens_final_version.py -g https://github.com/git/git --project_name GIT --cve CVE-2022-23521 --pre v2.30.6 --post v2.30.7 --vuln_desc description.txt --delta 100 --formats sh,c,h

```

Let's insert the prompts generated on output folder to ChatGPT:

```
cd output

for x in `ls`; do echo "Doing '$x'"; cat "$x" | clipbar; read; done

```

correctly finded
TP <--- this the only one prompt which gave a PoC so we start with this one

FP
FP

TN

TN (another issue described as "fixing potential resource exhaustion issue when processing formatting directives")



