# main.py

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Now you can access the variables using os.environ
api_key = os.environ.get("OPENAI_API_KEY")

if api_key:
    print("API Key successfully loaded.")
    # Example usage:
    # client = GeminiClient(api_key=api_key)
else:
    print("Failed to load GEMINI_API_KEY from the environment.")

