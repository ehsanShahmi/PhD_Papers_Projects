from datasets import load_dataset
from google import genai
from google.genai import types
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.luhn import LuhnSummarizer
from sumy.nlp.stemmers import Stemmer
from sumy.utils import get_stop_words
import nltk
# nltk.download('punkt_tab')
import pandas as pd
import numpy as np
import coverage as cv
import os
import subprocess
from pathlib import Path
import sys
import unittest
import io

##This part of the code is just setting up the Gemini-pro LLM:
# Set your API key
os.environ['GEMINI_API_KEY'] = '------'
# we can confirm the key was set (optional)
# print(os.environ['GEMINI_API_KEY'])
# The client gets the API key from the environment variable `GEMINI_API_KEY`, which is set above.
client = genai.Client()

# We load the dataset containing the security issues (Basim's SecVulEval dataset)
secVulEvalfull = pd.read_parquet("hf://datasets/arag0rn/SecVulEval/data/train-00000-of-00001.parquet")

# We load only the part of the dataset with vulnerabilites. no need for the fixed patches of that dataset.
secVulEval = secVulEvalfull[secVulEvalfull['is_vulnerable'] != False].reset_index(drop=True)
# Now secVulEval contains the vulnerable part of the dataset only - not the patched functions.


# We here take the first instance of this dataset. We take the "commit message" as the first security issue.
security_issues = secVulEval['commit_message']
security_issue = security_issues[0]
# print (security_issue)

def luhn_summarize(text, sentence_count=2):
    # Parse the input text
    parser = PlaintextParser.from_string(text, Tokenizer("english"))
    # Initialize summarizer with stemmer
    summarizer = LuhnSummarizer(Stemmer("english"))
    summarizer.stop_words = get_stop_words("english")
    # Generate summary
    summary = summarizer(parser.document, sentence_count)
    return summary


# After laoding, now we try to make a summary of it. This can either be done using an LLM, manually or by using libraries.
issue_summary = luhn_summarize(security_issue, 2)
print (issue_summary)
# for sentence in issue_summary:
#     print(sentence)