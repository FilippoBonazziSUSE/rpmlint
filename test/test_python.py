import pytest
from rpmlint.checks.PythonCheck import PythonCheck
from rpmlint.filter import Filter

from Testing import CONFIG, get_tested_mock_package


@pytest.fixture(scope='function', autouse=True)
def pythoncheck():
    CONFIG.info = True
    output = Filter(CONFIG)
    test = PythonCheck(CONFIG, output)
    yield output, test


@pytest.fixture
def output(pythoncheck):
    output, _test = pythoncheck
    yield output


@pytest.fixture
def test(pythoncheck):
    _output, test = pythoncheck
    yield test


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python2.7/site-packages/python-mypackage/doc': {'content': ''},
        '/usr/lib/python2.7/site-packages/python-mypackage/docs': {'content': ''},
        '/usr/lib/python3.10/site-packages/python-mypackage/doc': {'content': ''},
        '/usr/lib/python3.10/site-packages/python-mypackage/docs': {'content': ''},
        '/usr/lib64/python2.7/site-packages/python-mypackage/doc': {'content': ''},
        '/usr/lib64/python2.7/site-packages/python-mypackage/docs': {'content': ''},
        '/usr/lib64/python3.10/site-packages/python-mypackage/doc': {'content': ''},
        '/usr/lib64/python3.10/site-packages/python-mypackage/docs': {'content': ''}
    }
)])
def test_python_doc_in_package(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-doc-in-package /usr/lib/python2.7/site-packages/python-mypackage/doc' in out
    assert 'W: python-doc-in-package /usr/lib/python2.7/site-packages/python-mypackage/docs' in out
    assert 'W: python-doc-in-package /usr/lib/python3.10/site-packages/python-mypackage/doc' in out
    assert 'W: python-doc-in-package /usr/lib/python3.10/site-packages/python-mypackage/docs' in out
    assert 'W: python-doc-in-package /usr/lib64/python2.7/site-packages/python-mypackage/doc' in out
    assert 'W: python-doc-in-package /usr/lib64/python2.7/site-packages/python-mypackage/docs' in out
    assert 'W: python-doc-in-package /usr/lib64/python3.10/site-packages/python-mypackage/doc' in out
    assert 'W: python-doc-in-package /usr/lib64/python3.10/site-packages/python-mypackage/docs' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python2.7/site-packages/python-mypackage/doc/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 2},
        '/usr/lib/python2.7/site-packages/python-mypackage/docs/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 1},
        '/usr/lib64/python2.7/site-packages/python-mypackage/doc/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 2},
        '/usr/lib64/python2.7/site-packages/python-mypackage/docs/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 1},
        '/usr/lib/python3.10/site-packages/python-mypackage/doc/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 2},
        '/usr/lib/python3.10/site-packages/python-mypackage/docs/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 1},
        '/usr/lib64/python3.10/site-packages/python-mypackage/doc/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 2},
        '/usr/lib64/python3.10/site-packages/python-mypackage/docs/__init__.py': {'content': '', 'create_dirs': True, 'include_dirs': 1}
    }
)])
def test_python_doc_module_in_package(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-doc-in-package /usr/lib/python2.7/site-packages/python-mypackage/doc' not in out
    assert 'W: python-doc-in-package /usr/lib/python2.7/site-packages/python-mypackage/docs' not in out
    assert 'W: python-doc-in-package /usr/lib/python3.10/site-packages/python-mypackage/doc' not in out
    assert 'W: python-doc-in-package /usr/lib/python3.10/site-packages/python-mypackage/docs' not in out
    assert 'W: python-doc-in-package /usr/lib64/python2.7/site-packages/python-mypackage/doc' not in out
    assert 'W: python-doc-in-package /usr/lib64/python2.7/site-packages/python-mypackage/docs' not in out
    assert 'W: python-doc-in-package /usr/lib64/python3.10/site-packages/python-mypackage/doc' not in out
    assert 'W: python-doc-in-package /usr/lib64/python3.10/site-packages/python-mypackage/docs' not in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python2.7/site-packages/mydistutilspackage.egg-info': {'content': 'Metadata-Version: 2.1\nName: pythoncheck', 'create_dirs': False},
        '/usr/lib/python3.10/site-packages/mydistutilspackage.egg-info': {'content': 'Metadata-Version: 2.1\nName: pythoncheck', 'create_dirs': False},
        '/usr/lib64/python2.7/site-packages/mydistutilspackage.egg-info': {'content': 'Metadata-Version: 2.1\nName: pythoncheck', 'create_dirs': False},
        '/usr/lib64/python3.10/site-packages/mydistutilspackage.egg-info': {'content': 'Metadata-Version: 2.1\nName: pythoncheck', 'create_dirs': False}
    },
    real_files=True
)])
def test_python_distutils_egg_info(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'E: python-egg-info-distutils-style /usr/lib/python2.7/site-packages/mydistutilspackage.egg-info' in out
    assert 'E: python-egg-info-distutils-style /usr/lib/python3.10/site-packages/mydistutilspackage.egg-info' in out
    assert 'E: python-egg-info-distutils-style /usr/lib64/python2.7/site-packages/mydistutilspackage.egg-info' in out
    assert 'E: python-egg-info-distutils-style /usr/lib64/python3.10/site-packages/mydistutilspackage.egg-info' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python2.7/site-packages/doc': {'content': '', 'create_dirs': False},
        '/usr/lib/python2.7/site-packages/docs': {'content': '', 'create_dirs': False},
        '/usr/lib/python3.10/site-packages/doc': {'content': '', 'create_dirs': False},
        '/usr/lib/python3.10/site-packages/docs': {'content': '', 'create_dirs': False},
        '/usr/lib64/python2.7/site-packages/doc': {'content': '', 'create_dirs': False},
        '/usr/lib64/python2.7/site-packages/docs': {'content': '', 'create_dirs': False},
        '/usr/lib64/python3.10/site-packages/doc': {'content': '', 'create_dirs': False},
        '/usr/lib64/python3.10/site-packages/docs': {'content': '', 'create_dirs': False}
    }
)])
def test_python_doc_in_site_packages(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'E: python-doc-in-site-packages /usr/lib/python2.7/site-packages/doc' in out
    assert 'E: python-doc-in-site-packages /usr/lib/python2.7/site-packages/docs' in out
    assert 'E: python-doc-in-site-packages /usr/lib/python3.10/site-packages/doc' in out
    assert 'E: python-doc-in-site-packages /usr/lib/python3.10/site-packages/docs' in out
    assert 'E: python-doc-in-site-packages /usr/lib64/python2.7/site-packages/doc' in out
    assert 'E: python-doc-in-site-packages /usr/lib64/python2.7/site-packages/docs' in out
    assert 'E: python-doc-in-site-packages /usr/lib64/python3.10/site-packages/doc' in out
    assert 'E: python-doc-in-site-packages /usr/lib64/python3.10/site-packages/docs' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python2.7/site-packages/src': {'content': '', 'create_dirs': False},
        '/usr/lib/python3.10/site-packages/src': {'content': '', 'create_dirs': False},
        '/usr/lib64/python2.7/site-packages/src': {'content': '', 'create_dirs': False},
        '/usr/lib64/python3.10/site-packages/src': {'content': '', 'create_dirs': False}
    }
)])
def test_python_src_in_site_packages(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'E: python-src-in-site-packages /usr/lib/python2.7/site-packages/src' in out
    assert 'E: python-src-in-site-packages /usr/lib/python3.10/site-packages/src' in out
    assert 'E: python-src-in-site-packages /usr/lib64/python2.7/site-packages/src' in out
    assert 'E: python-src-in-site-packages /usr/lib64/python3.10/site-packages/src' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python2.7/site-packages/test': {'content': '', 'create_dirs': False},
        '/usr/lib/python2.7/site-packages/tests': {'content': '', 'create_dirs': False},
        '/usr/lib/python3.10/site-packages/test': {'content': '', 'create_dirs': False},
        '/usr/lib/python3.10/site-packages/tests': {'content': '', 'create_dirs': False},
        '/usr/lib64/python2.7/site-packages/test': {'content': '', 'create_dirs': False},
        '/usr/lib64/python2.7/site-packages/tests': {'content': '', 'create_dirs': False},
        '/usr/lib64/python3.10/site-packages/test': {'content': '', 'create_dirs': False},
        '/usr/lib64/python3.10/site-packages/tests': {'content': '', 'create_dirs': False}
    }
)])
def test_python_tests_in_site_packages(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'E: python-tests-in-site-packages /usr/lib/python2.7/site-packages/test' in out
    assert 'E: python-tests-in-site-packages /usr/lib/python2.7/site-packages/tests' in out
    assert 'E: python-tests-in-site-packages /usr/lib/python3.10/site-packages/test' in out
    assert 'E: python-tests-in-site-packages /usr/lib/python3.10/site-packages/tests' in out
    assert 'E: python-tests-in-site-packages /usr/lib64/python2.7/site-packages/test' in out
    assert 'E: python-tests-in-site-packages /usr/lib64/python2.7/site-packages/tests' in out
    assert 'E: python-tests-in-site-packages /usr/lib64/python3.10/site-packages/test' in out
    assert 'E: python-tests-in-site-packages /usr/lib64/python3.10/site-packages/tests' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/flit-3.8.0.dist-info/METADATA': {
            'content': """
Requires-Dist: flit_core >=3.8.0
Requires-Dist: requests
Requires-Dist: docutils
Requires-Dist: tomli-w
Requires-Dist: sphinx ; extra == "doc"
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'python-flit_core',
            'python-requests',
            'python-tomli-w',
            'python310-docutils',
        ],
    },
)])
def test_python_dependencies_metadata(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-missing-require' not in out
    assert 'W: python-leftover-require' not in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/icecream-2.1.3-py3.10.egg-info/requires.txt': {
            'content': """
asttokens>=2.0.1
colorama>=0.3.9
executing>=0.3.1
pygments>=2.2.0
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'asttokens>=2.0.1',
            'colorama>=0.3.9',
            'executing>=0.3.1',
            'pygments>=2.2.0',
        ],
    },
)])
def test_python_dependencies_requires(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-missing-require' not in out
    assert 'W: python-leftover-require' not in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/jupyter_server_fileid-0.9.0.dist-info/METADATA': {
            'content': """
Requires-Python: >=3.7
Requires-Dist: jupyter-events>=0.5.0
Requires-Dist: jupyter-server<3,>=1.15
Requires-Dist: click; extra == 'cli'
Requires-Dist: jupyter-server[test]<3,>=1.15; extra == 'test'
Requires-Dist: pytest; extra == 'test'
Requires-Dist: pytest-cov; extra == 'test'
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'python-jupyter-events',
            'python-jupyter-server',
            'python-click',
            'python-jupyter-server',
            'python-pytest',
            'python-pytest-cov',
        ],
    },
)])
def test_python_dependencies_metadata2(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-missing-require' not in out
    assert 'W: python-leftover-require' not in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/jupyter_server_fileid-0.9.0.dist-info/METADATA': {
            'content': """
Requires-Dist: distro
Requires-Dist: packaging
Requires-Dist: setuptools>=42.0.0
Requires-Dist: tomli; python_version < '3.11'
Requires-Dist: typing-extensions>=3.7; python_version < '3.8'
Requires-Dist: wheel>=0.32.0
Requires-Dist: coverage[toml]>=4.2; extra == 'cov'
Requires-Dist: pytest-cov>=2.7.1; extra == 'cov'
Requires-Dist: pygments; extra == 'docs'
Requires-Dist: sphinx-issues; extra == 'docs'
Requires-Dist: sphinx-rtd-theme>=1.0; extra == 'docs'
Requires-Dist: sphinx>=4; extra == 'docs'
Requires-Dist: sphinxcontrib-moderncmakedomain>=3.19; extra == 'docs'
Requires-Dist: ubelt>=0.8.2; extra == 'doctest'
Requires-Dist: xdoctest>=0.10.0; extra == 'doctest'
Requires-Dist: build>=0.7; extra == 'test'
Requires-Dist: cython>=0.25.1; extra == 'test'
Requires-Dist: importlib-metadata; python_version < '3.8' and extra == 'test'
Requires-Dist: pytest-mock>=1.10.4; extra == 'test'
Requires-Dist: pytest-virtualenv>=1.2.5; extra == 'test'
Requires-Dist: pytest>=6.0.0; extra == 'test'
Requires-Dist: requests; extra == 'test'
Requires-Dist: virtualenv; extra == 'test'
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'python-distro',
            'python-packaging',
            'python-setuptools',
            'python-tomli',
            'python-typing-extensions',
            'python-wheel',
            'python-coverage',
            'python-pytest-cov',
            'python-pygments',
            'python-sphinx-issues',
            'python-sphinx-rtd-theme',
            'python-sphinx',
            'python-sphinxcontrib-moderncmakedomain',
            'python-ubelt',
            'python-xdoctest',
            'python-build',
            'python-cython',
            'python-importlib-metadata',
            'python-pytest-mock',
            'python-pytest-virtualenv',
            'python-pytest',
            'python-requests',
            'python-virtualenv',
        ],
    },
)])
def test_python_dependencies_metadata3(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-missing-require' not in out
    assert 'W: python-leftover-require' not in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/jupyter_server_fileid-0.9.0.dist-info/METADATA': {
            'content': """
Requires-Dist: jsonschema[format-nongpl]>=3.2.0
Requires-Dist: python-json-logger>=2.0.4
Requires-Dist: pyyaml>=5.3
Requires-Dist: rfc3339-validator
Requires-Dist: rfc3986-validator>=0.1.1
Requires-Dist: traitlets>=5.3
Provides-Extra: cli
Requires-Dist: click; extra == 'cli'
Requires-Dist: rich; extra == 'cli'
Provides-Extra: docs
Requires-Dist: jupyterlite-sphinx; extra == 'docs'
Requires-Dist: myst-parser; extra == 'docs'
Requires-Dist: pydata-sphinx-theme; extra == 'docs'
Requires-Dist: sphinxcontrib-spelling; extra == 'docs'
Provides-Extra: test
Requires-Dist: click; extra == 'test'
Requires-Dist: coverage; extra == 'test'
Requires-Dist: pre-commit; extra == 'test'
Requires-Dist: pytest-asyncio>=0.19.0; extra == 'test'
Requires-Dist: pytest-console-scripts; extra == 'test'
Requires-Dist: pytest-cov; extra == 'test'
Requires-Dist: pytest>=7.0; extra == 'test'
Requires-Dist: rich; extra == 'test'
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'python-jsonschema',
            'python-python-json-logger',
            'python-pyyaml',
            'python-rfc3339-validator',
            'python-rfc3986-validator',
            'python-traitlets',
            'python-click',
            'python-rich',
            'python-jupyterlite-sphinx',
            'python-myst-parser',
            'python-pydata-sphinx-theme',
            'python-sphinxcontrib-spelling',
            'python-click',
            'python-coverage',
            'python-pre-commit',
            'python-pytest-asyncio',
            'python-pytest-console-scripts',
            'python-pytest-cov',
            'python-pytest',
            'python-rich',
        ],
    },
)])
def test_python_dependencies_metadata4(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-missing-require' not in out
    assert 'W: python-leftover-require' not in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/icecream-2.1.3-py3.10.egg-info/requires.txt': {
            'content': """
asttokens>=2.0.1
colorama>=0.3.9
executing>=0.3.1
pygments>=2.2.0
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'asttokens>=2.0.1',
            'executing>=0.3.1',
            'pygments>=2.2.0',
        ],
    },
)])
def test_python_dependencies_missing_requires(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-missing-require' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/flit-3.8.0.dist-info/METADATA': {
            'content': """
Requires-Dist: flit_core >=3.8.0
Requires-Dist: requests
Requires-Dist: docutils
Requires-Dist: tomli-w
Requires-Dist: sphinx ; extra == "doc"
Requires-Dist: sphinxcontrib_github_alt ; extra == "doc"
Requires-Dist: pygments-github-lexers ; extra == "doc"
Requires-Dist: testpath ; extra == "test"
Requires-Dist: responses ; extra == "test"
Requires-Dist: pytest>=2.7.3 ; extra == "test"
Requires-Dist: pytest-cov ; extra == "test"
Requires-Dist: tomli ; extra == "test"
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'python3-flit-core',
            'python3-requests',
            'python3-tomli-w',
        ],
    },
)])
def test_python_dependencies_missing_metadata(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-missing-require' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/icecream-2.1.3-py3.10.egg-info/requires.txt': {
            'content': """
asttokens>=2.0.1
colorama>=0.3.9
executing>=0.3.1
pygments>=2.2.0
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'python3-asttokens >= 2.0.1',
            'python3-colorama >= 0.3.9',
            'python3-executing >= 0.3.1',
            'python3-poetry',
            'python3-pygments >= 2.2.0',
        ],
    },
)])
def test_python_dependencies_leftover1(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-leftover-require' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        '/usr/lib/python3.10/site-packages/flit-3.8.0.dist-info/METADATA': {
            'content': """
Requires-Dist: flit_core >=3.8.0
Requires-Dist: requests
Requires-Dist: docutils
Requires-Dist: tomli-w
Requires-Dist: sphinx ; extra == "doc"
Requires-Dist: sphinxcontrib_github_alt ; extra == "doc"
Requires-Dist: pygments-github-lexers ; extra == "doc"
Requires-Dist: testpath ; extra == "test"
Requires-Dist: responses ; extra == "test"
Requires-Dist: pytest>=2.7.3 ; extra == "test"
Requires-Dist: pytest-cov ; extra == "test"
Requires-Dist: tomli ; extra == "test"
""",
            'create_dirs': True
        },
    },
    real_files=True,
    header={
        'requires': [
            'python3-docutils',
            'python3-flit-core',
            'python3-poetry',
            'python3-requests',
            'python3-tomli-w',
        ],
    },
)])
def test_python_dependencies_leftover2(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-leftover-require' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        'usr/lib/python3.9/site-packages/blinker/__pycache__/base.cpython-310.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/base.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/base.cpython-39.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/__init__.cpython-310.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/__init__.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/__init__.cpython-39.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_saferef.cpython-310.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_saferef.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_saferef.cpython-39.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_utilities.cpython-310.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_utilities.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_utilities.cpython-39.pyc': {'content': ''},
    }
)])
def test_python_pyc_multiple_versions(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-pyc-multiple-versions expected: 310' in out


@pytest.mark.parametrize('package', [get_tested_mock_package(
    files={
        'usr/lib/python3.9/site-packages/blinker/__pycache__/base.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/base.cpython-39.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/__init__.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/__init__.cpython-39.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_saferef.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_saferef.cpython-39.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_utilities.cpython-39.opt-1.pyc': {'content': ''},
        'usr/lib/python3.9/site-packages/blinker/__pycache__/_utilities.cpython-39.pyc': {'content': ''},
    }
)])
def test_python_pyc_single_version(package, pythoncheck):
    output, test = pythoncheck
    test.check(package)
    out = output.print_results(output.results)
    assert 'W: python-pyc-multiple-versions' not in out
