import sys
import os
import argparse
import re

import subprocess


import nltk
from nltk import word_tokenize as nlp


### 
## Utils
#

repo_folder = "repo_folder"

class WrapExp(Exception):
  pass



def check_output(cmd):
  return subprocess.check_output([
    "/bin/sh", 
    "-c",
    cmd
  ]).decode('utf-8').strip()


def check_tool(tool):
  """
    Check if 'tool' is present

  """
  rets = check_output("which {}".format(tool)).strip()
  if rets == '' :
    raise WrapExp("Can't find '{}' command".format(tool))


def do_git_clone(url, remove_folder=False):
  """
    Do git clone on 'repo_folder'

  """
  if remove_folder :
    _ = check_output("rm -rf {}".format(repo_folder))
  if os.path.isdir(repo_folder) :
    return
  rets = check_output("git clone {} {}; echo $?".format(url, repo_folder))
  ret_code = int(rets.split("\n")[-1])
  if ret_code :
    raise WrapExp("Can't git clone on '{}'".format(url))


def do_save_git_diff(pre_version, post_version, fmts_file=''):
  """
    Return the diff outputs
     - diff on pre and post versions (tag or commit)
     - skip those not matching file formats

  """
  cmd = f"git --no-pager diff {pre_version} {post_version}; echo $?"
  rets = check_output(cmd).split("\n")
  ret_code = int(rets[-1])
  if ret_code :
    raise WrapExp(f"Can't git diff on '{pre_version}' and '{post_version}'")
  #
  starts_with = lambda x : x.startswith("diff --git ")
  ends_with = lambda x : True
  if fmts_file :
    fmts = "\.({})$".format(
      "|".join([x.strip() for x in fmts_file.lower().split(",")])
    )
    ends_with = lambda x : re.search(fmts,x) != None
  #
  prev_index = -1
  output = []
  for i,x in enumerate(rets):
    if starts_with(x) :
      if prev_index > -1 :
        diff_now = rets[prev_index]
        if ends_with(diff_now.split(" ")[2].lower()) :
          output.append("\n".join(rets[prev_index:i]))
      prev_index = i

  diff_now = rets[prev_index]
  if ends_with(diff_now.split(" ")[2].lower()) :
    output.append("\n".join(rets[prev_index:i+1]))

  return output



### 
## Prompt
#

pre_version_ph = "$$PRE_VERSION$$"
post_version_ph = "$$POST_VERSION$$"
proj_name_ph = "$$PROJ_NAME$$"
git_url_ph = "$$GIT_URL$$"
vuln_desc_ph = "$$VULN_DESC$$"
diff_file_ph = "$$DIFF_FILE$$"

placeholder_list = [
  pre_version_ph,
  post_version_ph,
  proj_name_ph,
  git_url_ph,
  vuln_desc_ph,
  diff_file_ph
]

assistant = "Aa a security code auditor and expert security researcher, you are my assistant."
instruction_head = assistant + "\n" + \
  "I am analyzing version {0} and {1} of the {2} project which is hosted on {3}, and i found a" +\
  " vulnerability on version {0}, that is: \"{4}\"\n" +\
  "The following diff file created with diff command is given between version {0} (vulnerable)" +\
  " and the {1} (patched)." 

instruction = instruction_head + " Find where is the vulnerability and maybe give an example\n\n" +\
  "```\n" +\
  "{5}\n" +\
  "```\n"

instruction = instruction.format(*placeholder_list)


def get_description(arg):
  with open(arg, "r") as fp :
    rets = fp.read().strip()
  return rets

### 
## Tokenize and multi-part file support
#

part_counter_ph = "$$COUNTER$$"

instruction_token = instruction_head + " From now and on, I will upload the diff file splitted as follows:\n" +\
  "```\n" +\
  "Part: <file-part>\n" +\
  "Text:\n" +\
  "<file-content>\n" +\
  "EOF@#^#@\n" +\
  "```\n" +\
  "With  '<file-part>' as the diff file's content number with '0' denoting the last part, and '<file-content>'" +\
  " as the diff file's content, and 'EOF@#^#@' as the separator to terminate a section. After i ended to upload" +\
  " source codes i will send the line:\n" +\
  "```\n" +\
  "EOF@#:#@\n" +\
  "EOF@#:#@\n" +\
  "```\n" +\
  "After i do that i want you find where is the vulnerability and maybe give an example"
instruction_token = instruction_token.format(*placeholder_list)

instruction_token_body = "```\nPart: {0}\nText:\n{1}\nEOF@#^#@\n```".format(part_counter_ph, diff_file_ph)
instruction_token_tail = "```\nPart: {0}\nText:\n{1}\nEOF@#:#@\nEOF@#:#@\n```".format(part_counter_ph, diff_file_ph)


delta = 10 # the error i've imagined inserted somewhere i don't know
max_tokens = 4096


def do_test_needs_tokenizer(text) :
  tokens = nlp(text)
  return len(tokens) >= max_tokens


def do_save_splitted_request(text, instruction):
  text_lines = text.split("\n")
  header_file = text_lines[0]
  text_lines = text_lines[1:]

  output = []
  output_token_len = []
  prev_index = -1
  for i,x in enumerate(text_lines):
    if x.startswith("@@ ") :
      if prev_index > -1 :
        output.append("\n".join(text_lines[prev_index:i]))
        output_token_len.append(len(nlp(output[-1])) + 1)

      prev_index = i

  output.append("\n".join(text_lines[prev_index:i+1]))
  output_token_len.append(len(nlp(output[-1])) + 1)
  header_token_len = len(nlp(header_file)) + 1

  token_prompt = len(nlp(instruction)) + 1 +\
    len(nlp(instruction_token_body.replace(part_counter_ph, "100")))
  
  assert [True for x in output_token_len if x > max_tokens] == [], "Function too large"
  assert token_prompt < max_tokens, "Prompt model does have amount of tokens greater than 4096"

  new_output = []
  first_req = True
  prev_index = 0
  current_tokens = token_prompt + header_token_len

  for i,x in enumerate(output_token_len) :
    next_tokens = current_tokens + x

    if next_tokens > max_tokens :
      tmp_result = header_file + "\n" + "\n".join(output[prev_index:i])
      tmp_output = instruction_token_body.replace(diff_file_ph, tmp_result)

      if first_req :
        tmp_output = instruction + "\n" + tmp_output
        first_req = False

      new_output.append(tmp_output)
      current_tokens = x + header_token_len
      prev_index = i

    else :
      current_tokens = next_tokens

  tmp_result = header_file + "\n" + "\n".join(output[prev_index:i+1])
  tmp_output = instruction_token_tail.replace(diff_file_ph, tmp_result)
  new_output.append(tmp_output)

  # enforce tokens check
  for i,x in enumerate(new_output):
    x = len(nlp(x.replace(part_counter_ph, str(len(new_output)-(i+1)))))
    assert x < max_tokens, "Index '{}' has amount greater than {}".format(i, max_tokens)

  for i,x in enumerate(new_output):
    with open(f"{str(i).rjust(2, '0')}.txt", "w") as fp :
      fp.write(x.replace(part_counter_ph, str(len(new_output)-(i+1))))



##################### 

if __name__ == "__main__" :
  parser = argparse.ArgumentParser(
    description="%s: Downloader Tool" % sys.argv[0]
  )
  parser.add_argument(
    "-g",
    "--git",
    required=True,
    help="Git url repository to git clone"
  )
  parser.add_argument(
    "--cve",
    required=True,
    help="Insert CVE number. The files are saved based on that"
  )
  parser.add_argument(
    "--pre",
    required=True,
    help="Software version still unpatched"
  )
  parser.add_argument(
    "--post",
    required=True,
    help="Software version patched"
  )
  parser.add_argument(
    "--formats",
    default="",
    help="File formats that we're interested in with ',' as separator for multiple choices (e.g. py, c,cpp,h,hpp)"
  )
  parser.add_argument(
    "--remove",
    default=False,
    action="store_true",
    help=
      "Delete the temporary folder before git cloning on it '{}' (default:False)".format(
        repo_folder
      )
  )
  parser.add_argument(
    "--output",
    default="output",
    help="Folder where results are saved"
  )
  parser.add_argument(
    "--project_name",
    required=True,
    help="Name of the project (e.g. GO, GO golan, rust)"
  )
  parser.add_argument(
    "--vuln_desc",
    required=True,
    help="Vulnerability description"
  )
  parser.add_argument(
    "--delta",
    default=delta,
    type=int,
    help="Number to sub to max_tokens amount which is 4096 (default: {})".format(delta)
  )

  args = parser.parse_args()

  pre_version = args.pre
  post_version = args.post
  fmts_file = args.formats
  cve = args.cve

  args.vuln_desc = get_description(args.vuln_desc)
  delta = args.delta
  max_tokens -= delta

  if not os.path.isdir(args.output) :
    os.mkdir(args.output)

  try :
    check_tool("git")
    do_git_clone(args.git, args.remove)
    os.chdir(repo_folder)
    output = do_save_git_diff(pre_version, post_version, fmts_file)
    os.chdir("..")

    lookup_replace = {
      "pre_version_ph" : "pre",
      "post_version_ph" : "post",
      "proj_name_ph" : "project_name",
      "git_url_ph" : "git",
      "vuln_desc_ph" : "vuln_desc"
    }

    for k,v in lookup_replace.items() :
      instruction = instruction.replace(
        globals()[k], 
        getattr(args, v)
      )
      instruction_token = instruction_token.replace(
        globals()[k], 
        getattr(args, v)
      )

    for i,x in enumerate(output) :
      x_out = instruction.replace(diff_file_ph, x)
      cve_id = f"{cve}_{str(i).rjust(2,'0')}"

      if do_test_needs_tokenizer(x_out) :
        print("[!] Tokenizing on '{}'".format(cve_id))

        os.chdir(f"{args.output}")
        if not os.path.isdir(cve_id) :
          os.mkdir(cve_id)

        os.chdir(cve_id)
        do_save_splitted_request(x, instruction_token)

        os.chdir("../..")

      else :
        with open(f"{args.output}/{cve_id}.txt","w") as fp:
          x = instruction.replace(diff_file_ph, x)
          fp.write(x)

    print("[+] Done")

  except WrapExp as ex :
    print("[x] Exception: {}".format(ex))



