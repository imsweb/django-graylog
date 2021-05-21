import re

from setuptools import setup

with open("README.md", "r") as readme:
    long_description = readme.read()

with open("django_graylog.py", "r") as src:
    version = re.match(r'.*__version__ = "(.*?)"', src.read(), re.S).group(1)

setup(
    name="django-graylog",
    version=version,
    description="Graylog middleware for Django.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Dan Watson",
    author_email="watsond@imsweb.com",
    url="https://github.com/imsweb/django-graylog",
    license="MIT",
    py_modules=["django_graylog"],
    install_requires=[
        'contextvars;python_version<"3.7"',
    ],
    extras_require={
        "http": ["requests"],
        "ua": ["ua-parser"],
        "all": ["requests", "ua-parser"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
    ],
)
