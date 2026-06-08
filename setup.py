from setuptools import setup, find_packages

setup(
    name="cvelens",
    version="1.0.0",
    description="Vulnerability Intelligence Engine — powered by Groq",
    author="h4ckl07d",
    python_requires=">=3.8",
    install_requires=[
        "groq",
        "requests",
        "python-dotenv",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "cvelens=cvelens:main",   # maps `cvelens` command → main() in cvelens.py
        ],
    },
)