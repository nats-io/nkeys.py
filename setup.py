from setuptools import setup

# Metadata goes in pyproject.toml.
# These are here for GitHub's dependency graph and help with setuptools support in some environments.
setup(
    name="nkeys",
    version='0.2.1',
    license='Apache 2 License',
    packages=['nkeys'],
    install_requires=['pynacl'],
    zip_safe=True,
)
