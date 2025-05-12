# Configuration file for the Sphinx documentation builder.
import os
import sys
sys.path.insert(0, os.path.abspath('../..')) # Adjust depending on where conf.py is vs project root
sys.path.insert(0, os.path.abspath('../')) # Point to the parent directory of 'docs' to find 'networking_tester' package

project = 'networking_tester'
copyright = '2025, Juan C' # Replace with your name/org
author = 'Juan C'
release = '0.2.0' # Get from ConfigManager or pyproject.toml ideally

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon', # For Google/NumPy style docstrings
    'sphinx.ext.intersphinx',
    'sphinx.ext.viewcode',
    'sphinx_rtd_theme',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Autodoc settings
autodoc_member_order = 'bysource'
autodoc_default_options = {
    'members': True,
    'undoc-members': True,
    'private-members': False,
    'special-members': '__init__',
    'show-inheritance': True,
}

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = False # Or True if you prefer NumPy style
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True