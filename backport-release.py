"""
 ==================================================================
 Subprocess:The subprocess module allows you to spawn new processes,
 connect to their input/output/error pipes, and obtain their return
 codes.
 Time:This module provide time related functions.i.e clock_gettime()
 clock_settime(),ctime([second]).
 OS:This module provides a protable way of using os dependent func.
 Logging: Logging facility for python.
 ==================================================================
"""
import subprocess
import time
import sys
import os
import json
import argparse
import logging

logging.basicConfig(level=logging.DEBUG)

"""
 ==================================================================
 Parse the command line arguments.
 ==================================================================
"""
parser = argparse.ArgumentParser()
parser.add_argument('--rev', metavar='<name>', type=int, default=int(0),
                    help='Create with Custom Revision[R] in the tag, \
                    YYMMDD.[R]. Ex: Create .1 release for 231204.0 --> 231204.1 \
                    Default is 0')

args = parser.parse_args()

# Load config json file
try:
    with open(os.path.join(sys.path[0], "config.json"),'r') as f:
        data = json.load(f)
except IOError as e:
    logging.info("No such file: {0.config.json}".format(e))
    sys.exit()

SOURCE_DIR = data['source_dir']
BACKPORT_DIR = data['backport_dir']
REL_DIR = data['releases_dir']
HEADERS = data['headers_repo']
BACKPORT_REPO = data['xekmd_repo']

def find_base_dir(start_path, target_repo_name):
	cur = os.path.abspath(start_path)
	while True:
		candidate = os.path.join(cur, target_repo_name)
		if os.path.isdir(candidate):
			return cur + os.path.sep
		parent = os.path.dirname(cur)
		if parent == cur:
			break
		cur = parent
	return None

detected_base = find_base_dir(sys.path[0], BACKPORT_REPO)
if detected_base:
	BASE_DIR = detected_base
else:
	logging.error("Could not detect base directory")
	sys.exit(1)

MAIL = data['mail']
FROM_ADDR = data['from_addr']
HEADERS_BRANCH = data['headers_branch']['header_branch_name']
URL = "intel-innersource/"
# Get the current time in GMT (Greenwich Mean Time) format
Date = time.strftime("%y%m%d", time.gmtime())

#predefined data
TAG = "XE_{0}_{1}.{2}"
FULL_XE_TAG = "xeb_{0}"
GEN_OUT = "out_backport_{0}".format(time.strftime("%y%m%d_%H%M%S"))
GENTREE_CMD = [
	sys.executable,
	os.path.join(os.getcwd(), BACKPORT_DIR, "gentree.py"),
	os.path.join(os.getcwd(), SOURCE_DIR, "kernel"),
	os.path.join("../../", GEN_OUT),
	"--verbose",
	"--gitdebug",
	"--clean",
]
PUBLISH_BACKPORT = "cp -rvf {0}{1}/* {2}/".format(BASE_DIR, GEN_OUT, os.path.join(BASE_DIR, BACKPORT_REPO, REL_DIR))
PR_LINK = "https://github.com/" + URL + BACKPORT_REPO + "/pull/"
CLEAN_GEN_OUT = "rm -rf {0}out_backport_*".format(BASE_DIR)

MSG = "{0}\n\n\
\
Generation Information: \n\
XeKMD-Backport-Tag: {1}\n\
Backports Tag: {2}\n\
Backports Branch: {3}\n\
Backports Head: {4}\n\
\
PR-Generated: Auto Backported."

# Flags to identify the failure
is_build_failure = False

"""
 =======================================================================
 Run the provided setup-worktree script with the create-worktree command.
 returns True on success
 False on failure (non-zero exit codes)
 =======================================================================
"""
def create_worktree():
	try:
		subprocess.check_call("git -C {0} checkout -f origin/master -b master".format(os.getcwd()), shell=True)
	except subprocess.CalledProcessError as err:
		logging.info("Branch already exists")
		try:
			subprocess.check_call("git -C {0} checkout -f master".format(os.getcwd()), shell=True)
		except subprocess.CalledProcessError as err:
			logging.info("Already checked out to branch: master")
	subprocess.check_call("git -C {0} pull".format(os.getcwd()), shell=True)
	try:
		subprocess.check_call(["./setup-worktree.sh", "create-worktree"])
		return True
	except subprocess.CalledProcessError as e:
		logging.error("Worktree creation failed with exit code %d", e.returncode)
		return False

"""
 =======================================================================
 Run the provided setup-worktree script with the clean-worktree command
 =======================================================================
"""
def clean_worktree():
	try:
		subprocess.check_call(["./setup-worktree.sh", "clean-worktree"])
		sys.exit()
	except subprocess.CalledProcessError as e:
		logging.error("Worktree cleanup failed with exit code %d", e.returncode)
	sys.exit()

"""
 =========================================================================
 generate_backport function is used for executing the gentree command and
 creating the backported source.
 returns:
    True on success
    False on any failure
 =========================================================================
"""
def generate_backport():
	global backport_head
	global backport_branch
	backport_dir = os.path.join(os.getcwd(), BACKPORT_DIR)
	backport_head = subprocess.check_output("git rev-parse --short HEAD",
                                            cwd=backport_dir, shell=True, encoding='UTF-8').strip()
	backport_branch = subprocess.check_output("git rev-parse --abbrev-ref HEAD", 
											cwd=backport_dir, shell=True, encoding='UTF-8').strip()
	result = subprocess.run(GENTREE_CMD, cwd=backport_dir)
	if result.returncode:
		subprocess.check_call('( echo "Subject:Hunk Failure\n";cat {0}{1}_DKMS.log | tail -40;uuencode {0}{1}_DKMS.log backport_{1}_$(date +%y%m%d-%H:%M:%S).log ) | sendmail -f {3} {2}'.format(BASE_DIR, "6.14.11-250811.7", MAIL, FROM_ADDR), shell=True)
		return False
	return True

"""
 ==============================================================================
 Compiles the headers repo with latest kernel version
 returns:
    True in case of success
    False in case of any failure
 ==============================================================================
"""
def verify_build():
	global is_build_failure
	headers_path = os.path.join(BASE_DIR, HEADERS)
	try:
		if not os.path.isdir(headers_path):
			logging.info('Headers repo not found at %s; cloning %s', headers_path, HEADERS)
			subprocess.check_call(['git', 'clone', HEADERS, BASE_DIR])
		logging.info('Checking out headers branch %s in %s', HEADERS_BRANCH, headers_path)
		subprocess.check_call(['git', '-C', headers_path, 'checkout', '-f', HEADERS_BRANCH])
		compile_script = os.path.join(BASE_DIR, GEN_OUT, 'compile.sh')
		if not os.path.isfile(compile_script):
			logging.error('File not found in releases directory: %s', compile_script)
			return False
		subprocess.check_call(['bash', compile_script, headers_path], cwd=os.path.join(BASE_DIR, GEN_OUT))
		return True
	except subprocess.CalledProcessError as e:
		logging.error('Compilation Failure: %s', e)
		is_build_failure = True
		return False

"""
=====================================================================
 create_pr is used to create the pull request
 returns:
    PR number in string format on success
    None in case of failure
=====================================================================
"""
def create_pr():
	global PR_LINK
	pr_num_string = None
	head = subprocess.check_output("git rev-parse --abbrev-ref HEAD", shell=True, encoding='UTF-8').strip()
	result = subprocess.run([
		"dt", "pr", "create",
		"--repo={0}".format(URL + BACKPORT_REPO),
		"--base={0}".format(rel_branch),
		"--head={0}".format(head)
	], capture_output=True, text=True)
	time.sleep(1)
	if result.returncode:
		logging.critical("Create pull request failed:%s!\n", result.stderr)
		return pr_num_string

	lines = result.stdout.split('\n')
	for i in range(len(lines)):
		if lines[i].startswith("Pull request created:"):
			line = lines[i]
			pr_num_string = line.split("/")[-1]
			PR_LINK = PR_LINK + pr_num_string
	return pr_num_string

"""
 =============================================================================
 create_release function is used for creating the PR on release repository
 * Copying the out directory into backport.release repo.
 * Commit the changes and create the PR for review.
 =============================================================================
"""
def create_release():
	global TAG
	REL_COMMIT = "XE-KMD Backport-Release: xebr-{0}.{1}.0".format(COMMIT_TAG, args.rev)
	logging.info("Started the release process!\n")
	result = subprocess.run((["git", "pull"]), capture_output=True, text=True)
	if result.returncode:
		logging.info("Releases git pull command failed:%s!\n", result.stderr)
		sys.exit()
	logging.info("Adding all files into git!\n")
	subprocess.run(["git", "add", "-A"])
	subprocess.run(["git", "commit", "-s", "-m", MSG.format(REL_COMMIT, COMMIT_TAG, FULL_XE_TAG.format(COMMIT_TAG), backport_branch, backport_head)])
	time.sleep(1)
	logging.info("Commit added successfully!\n")
	PR_NUM = create_pr()
	if PR_NUM:
		logging.info("PR:%s successfully created!\n", PR_LINK)
		release_head = subprocess.check_output("git rev-parse --short HEAD",
                                                shell=True, encoding='UTF-8').strip()
		tag = TAG.format(COMMIT_TAG, Date, args.rev)
		if create_push_tag(release_head, tag, rel_branch):
			logging.info("tag is created and pushed on release repo")
			try:
				subprocess.check_call('git -C {0} push origin {1}'.format(os.path.join(BASE_DIR, BACKPORT_REPO, BACKPORT_DIR), tag), shell = True)
			except subprocess.CalledProcessError as err:
				logging.critical("Error while pushing backporting tag..!\n")
				return False
			return True
		else:
			logging.critical("Error while pushing backporting release tag..!\n")
			return False
	return True

"""
 ========================================================================
 create_push_tag is used for doing creating the tag and pushing the tag.
 args.1 => head -> commit_sha of the repository to which tag has to be created
 args.2 => tag -> Tag which needs to be created and pushed
 args.3 => branch -> branch name of the given commit sha
 returns:
    True on success
    False on Failure
 ========================================================================
"""
def create_push_tag(head, tag, branch):
    subprocess.check_call("git fetch --all", shell=True)
    subprocess.check_call("git reset --hard origin/{0}".format(branch), shell=True)
    if not subprocess.check_call('git tag -a {0} {1} -m "Create tag {0} for {1}"'.format(tag, head), shell=True):
        if not subprocess.check_call("git push origin {0}".format(tag), shell=True):
            logging.info("Tag:%s pushed successfully!\n", tag)
            return True
        else:
            logging.critical("Unable to push the tag:%s\n", tag)
            return False
    else:
        logging.critical("Unable to create the tag:%s\n", tag)
        return False

if __name__ == "__main__":
	global rel_branch
	global COMMIT_TAG
	result = create_worktree()
	if not result:
		logging.error("Cleaning up worktree due to failure")
		clean_worktree()
	else:
		backport_path = os.path.join(os.getcwd(), SOURCE_DIR)
		COMMIT_TAG = subprocess.check_output("git describe --abbrev=0 --tags",
                                            shell=True, cwd=backport_path, encoding='UTF-8').strip()
		if not COMMIT_TAG:
			logging.error("Failed to get the latest tag")
			clean_worktree()
		else:
			if generate_backport():
				os.chdir(BASE_DIR + GEN_OUT)
				rel_branch = subprocess.check_output("git rev-parse --abbrev-ref HEAD", cwd=os.path.join(BASE_DIR, BACKPORT_REPO, REL_DIR), shell=True, encoding='UTF-8').strip()
				subprocess.check_call("git -C {0} checkout -B {1}_temp origin/{1}".format(os.path.join(BASE_DIR, BACKPORT_REPO, REL_DIR), rel_branch), shell=True)
				subprocess.run([PUBLISH_BACKPORT], shell=True)
				os.chdir(os.path.join(BASE_DIR, BACKPORT_REPO))
				if not verify_build():
					clean_worktree()
				else:
					os.chdir(os.path.join(os.getcwd(),REL_DIR))
					if create_release():
						try:
							subprocess.run([CLEAN_GEN_OUT], shell=True)
						except subprocess.CalledProcessError:
							logging.error('Failed to clean out directory')
					else:
						logging.critical("\n==Failed to create PR on release branch==\n")
						sys.exit(1)
			else:
				logging.critical("\n==Got Hunk Failure on DII==\n")
				clean_worktree()