#!/usr/bin/env python
# Requires python 2.7. (Macports users: sudo port select --set python python27)

from __future__ import division

import math
import subprocess
import datetime
import urllib
import json
import argparse
import os
import re
from string import ljust, rjust

parser = argparse.ArgumentParser(description="Show hg blame for each line of a stack trace, along with nearby lines.")
parser.add_argument("-a", "--allthreads", dest="allthreads", action='store_true', help="show all threads (default: only the crashing thread)", default=False)
parser.add_argument("-c", "--context", dest="context", metavar="N", type=int, help="lines of context (default: 5)", default=5)
parser.add_argument("-R", "--repository", dest="repo", metavar="dir", default=None, help="local repository (default: guess a directory like ~/mozilla-central/ based on the repo name)")
parser.add_argument("input", help="Crash report ID, file containing the output of 'minidump_stackwalk -m', or file containing the output of gdb 'bt'")
args = parser.parse_args()

beginning_of_time = datetime.date(2007, 03, 22) # Mozilla's CVS->Hg migration
revDigits = 6 # mozilla-central has over 100000 changesets
today = datetime.date.today()

htmlPrologue = ""
htmlToc = ""
htmlMain = ""
htmlStylesheet = """
  <style>
  body { font-family: sans-serif; }
  h2.otherthread { background: salmon; }
  .line { white-space: pre; font-family: monospace; }
  .line.target { font-weight: bold; }
  .line > a { text-decoration: none; }
  .line > a:hover { text-decoration: underline; }
  .line > a.lineBlame { color: rgba(0, 0, 0, .2); }
  .line > a.fileDiff { color: rgba(0, 0, 255, .8) }
  </style>
"""

rawBlameCache = {}

# html_escape copied from http://wiki.python.org/moin/EscapingHtml
html_escape_table = {
    "&": "&amp;",
    '"': "&quot;",
    "'": "&apos;",
    ">": "&gt;",
    "<": "&lt;",
    }
def html_escape(text):
    """Produce entities within text."""
    return "".join(html_escape_table.get(c,c) for c in text)

def html_link(url, text, clazz=None, title=None):
    clazzAttr = (' class="' + clazz + '"' if clazz else '')
    titleAttr = (' title="' + title + '"' if title else '')
    hrefAttr = " href=\"" + html_escape(url) + "\""
    return "<a" + clazzAttr + titleAttr + hrefAttr + ">" + text + "</a>"


def processStack(stack):
    global htmlMain
    lastThreadSeen = None
    cachedChangeset = None
    for stackLine in stack:
        # minidump_stackwalk -m
        # Example:
        # 0|0|XUL|_cairo_image_surface_assume_ownership_of_data|hg:hg.mozilla.org/mozilla-central:gfx/cairo/cairo/src/cairo-image-surface.c:a42e9b001bc8|812|0x0
        a = stackLine.split("|")
        if len(a) == 7 and a[0].isdigit():
            threadNum = int(a[0])
            if lastThreadSeen is None:
                lastThreadSeen = threadNum
                htmlMain += "\n\n<h2 class='crashedthread'>Thread " + str(threadNum) + " (crashed)</h2>"
                print "\n\nThread " + str(threadNum) + " (crashed)"
            elif lastThreadSeen != threadNum:
                if args.allthreads:
                    lastThreadSeen = threadNum
                    htmlMain += "\n\n<h2 class='otherthread'>Thread " + str(threadNum) + "</h2>"
                    print "\n\nThread " + str(threadNum)
                else:
                    break

            #stackFrameNum = int(a[1])
            module = a[2]
            funName = a[3]

            b = a[4].split(":")
            if b[0] == "hg" and b[1].startswith("hg.mozilla.org/"):
                officialRepoName = b[1].split("/", 1)[1] # e.g. "mozilla-central"
                line = a[5]
                filename = b[2]
                changeset = b[3]
            else:
                officialRepoName = None
                line = None
                filename = None
                changeset = None

            showStackEntry(module, funName, line, filename, changeset, officialRepoName, None)

        elif stackLine.startswith("#"):
            # gdb "bt"
            # Example:
            # #1  0x0000000104ae1111 in str_localeCompare (cx=0x10bde7fb0, argc=0, vp=0x111a3a0a0) at /Users/jruderman/trees/mozilla-central/js/src/jsstr.cpp:779
            match = re.match(r"#\d+\s+(?:0x[0-9a-f]* in )?([^() ]*)(.*)", stackLine)
            funName = match.group(1)
            rest = match.group(2)

            match2 = re.match(r"(.*) at (.*mozilla-central/)(.*):(\d+)", rest)
            if match2:
                rest = match2.group(1)
                repo = match2.group(2)
                filename = match2.group(3)
                line = match2.group(4)
                officialRepoName = "mozilla-central" # ?
                cachedChangeset = cachedChangeset or subprocess.check_output(["hg", "-R", repo, "log", "--template", "{node}", "-r", "first(parents(.))"])[0:12]
                changeset = cachedChangeset
            else:
                filename = None
                line = None
                changeset = None
                officialRepoName = None
                repo = None

            showStackEntry(None, funName, line, filename, changeset, officialRepoName, repo)


def showStackEntry(module, funName, line, filename, changeset, officialRepoName, repo):
    global htmlMain
    modulePrefix = module + " ! " if module else ""
    print
    htmlMain += "\n<h3>" + html_escape(modulePrefix)

    if officialRepoName:
        if funName != "":
            mxrSearchLink = "https://mxr.mozilla.org/" + officialRepoName + "/search?string=" + urllib.quote_plus(funName.split("(")[0])
            mxrSearchLink = html_link(mxrSearchLink, html_escape(funName), "mxrSearch")
            htmlMain += mxrSearchLink
        else:
            htmlMain += "(unknown function)"

        if filename != "":
            mxrLineLink = "https://mxr.mozilla.org/" + officialRepoName + "/source/" + filename + "#" + line
            mxrLineLink = "(" + html_link(mxrLineLink, html_escape(filename + ":" + line), "mxrLine") + ")"
            htmlMain += " " + mxrLineLink + "</h3>\n\n"
            print modulePrefix + funName + " (" + filename + ":" + line + " @ " + changeset + ")"
            print
            if not "dist/include" in filename:
                showContext(filename, int(line), changeset, officialRepoName, repo)
        else:
            print modulePrefix + funName + " (unknown.file:" + line + ")"
            htmlMain += " (unknown.file:" + line + ")</h3>\n\n"
    else:
        print modulePrefix + funName + " (unknown repo)"
        htmlMain += html_escape(funName) + " (unknown repo)</h3>\n\n"


def showContext(filename, line, changeset, officialRepoName, repo):
    global htmlMain, rawBlameCache
    hashKey = changeset + filename
    if hashKey in rawBlameCache:
        rawBlame = rawBlameCache[hashKey]
    else:
        repo = repo or args.repo or findRepo(officialRepoName)
        rawBlame = subprocess.check_output(["hg", "-R", repo, "blame", "-c", "-d", "-q", "-u", "-n", "-r", changeset, repo + filename]).split("\n")
        rawBlameCache[hashKey] = rawBlame

    # Parse the output of "hg blame" for the lines we are interested in, e.g.
    #    arpad 24551 a206aff7a9c6 2009-02-03: #include "nsTArray.h"
    # The first two fields are space-padded, so we use split(None) on them. But we want the space-padding on the code itself.
    firstLineNum = max(line - args.context, 0)
    lastLineNum = min(line + args.context, len(rawBlame) - 1)
    for lineNum in range(firstLineNum, lastLineNum + 1):
        [commitUser, commitRev, commitChangeset, commitDateAndLine] = rawBlame[lineNum - 1].lstrip().split(None, 3)
        commitDate = commitDateAndLine[0:10]
        codeLine = commitDateAndLine[12:]
        ageFrac = freshness(commitDate)
        commitUserAndRev = rjust(commitUser, 12) + "@" + ljust(commitRev, revDigits)

        htmlColor = 'hsl(120, 100%, ' + str(int(100 - ageFrac*50)) + '%)'
        htmlBegin = '<div class="line' + (' target' if lineNum == line else '') + '" style="background: ' + htmlColor + '; color: black;">'
        htmlEnd = '</div>\n'
        htmlDiffURL = "https://hg.mozilla.org/" + officialRepoName + "/diff/" + commitChangeset + "/" + filename
        htmlDiffLink = html_link(htmlDiffURL, html_escape(commitUserAndRev), "fileDiff", title="Committed " + commitDate)
        htmlAnnotateURL = "https://hg.mozilla.org/" + officialRepoName + "/annotate/" + changeset + "/" + filename + "#l" + str(lineNum)
        htmlAnnotateLink = html_link(htmlAnnotateURL, rjust(str(lineNum), 5), "lineBlame")
        htmlMain += htmlBegin + htmlDiffLink + " " + htmlAnnotateLink + " " + html_escape(codeLine) + htmlEnd

        ageGroupStars = ljust("*" * int(ageFrac * 10), 10)
        print ageGroupStars + " " + commitUserAndRev + " [" + commitDate + "] " + codeLine

def freshness(dateStr):
    [y, m, d] = dateStr.split("-")
    date = datetime.date(int(y), int(m), int(d))
    dateFraction = (date - beginning_of_time).days / (today - beginning_of_time).days
    dateFraction = max(min(dateFraction, 1), 0)
    return dateFraction ** 3 # exaggerate the difference between recent changes


if args.repo:
    if not args.repo.endswith("/") and not args.repo.endswith("\\"):
        # os.sep?
        args.repo += "/"
    if not os.path.isdir(args.repo):
       raise Error("I can't find the local repository directory")

def findRepo(officialRepoName):
    guess = os.path.expanduser("~/" + officialRepoName + "/")
    if os.path.exists(guess + ".hg"):
        return guess
    raise Exception("Repo not specified, and my guess of " + guess + " isn't a local repo")


if os.path.exists(args.input):
    processStack(open(args.input))
    outfilename = "stackblame.html"
else:
    match = re.match(r"(bp-)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", args.input, flags=re.IGNORECASE)
    if match:
        crashReportID = match.group(2)
        print "Fetching crash report " + crashReportID
        jsonCrashReport = subprocess.check_output(["curl", "--silent", "https://crash-stats.mozilla.com/dumps/" + crashReportID + ".jsonz"])
        processStack(json.loads(jsonCrashReport).get("dump").split("\n"))
        outfilename = crashReportID + ".html"
        htmlPrologue = "<h1>Stack Blame for " + html_link("https://crash-stats.mozilla.com/report/index/" + crashReportID, "bp-" + crashReportID, "crashreport") + "</h1>"
    else:
        raise Exception("Input must be a crash report ID from crash-stats.mozilla.com (or a local file)")

# Write HTML
with open(outfilename, "w") as f:
    f.write("<!DOCTYPE html><title>Stack Blame</title>" + htmlStylesheet + htmlPrologue + htmlToc + htmlMain)
print
print "Created " + outfilename
