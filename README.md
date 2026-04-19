[![ PyPi ](https://github.com/Matbe34/py-nessus/actions/workflows/pynessus-publish.yml/badge.svg?event=release)](https://pypi.org/project/py-nessus-pro/)

# PyNessusPro

PyNessusPro is a Python module that provides a high-level interface for interacting with a Nessus vulnerability scanner. The module uses the Nessus REST API to perform various operations, such as creating and managing scans, retrieving scan metadata and reports, and searching for scans by name or date. It provides Nessus Professional with an interface to expand the read-omly API and be able to launch scans and modify them.

## Installation

To install PyNessusPro, simply run:

```
pip install py-nessus-pro
```

## Usage

To use PyNessusPro, you first need to create an instance of the `PyNessusPro` class, which represents a connection to a Nessus server. You can create an instance by providing the URL of the Nessus server, as well as your username and password:

```python
from py_nessus_pro import PyNessusPro

nessus_server = "https://nessus-server-url:8834"
username = "admin"
password = "password"

nessus = PyNessusPro(nessus_server, username, password)
```

Once you have created an instance of the `PyNessusPro` class, you can use its methods to perform various operations. For example, you can create a new scan by calling the `new_scan` method:

```python
scan_name = "My Scan"
scan_target = "127.0.0.1"
scan_folder = "Automatic Scan Test"

scan_index = nessus.new_scan(name=scan_name, target=scan_target, folder=scan_folder)
```

Once a scan is created it is assigned an ID for nessus but also an internal ID for PyNessus.\
The return value for `nessus.new_scan()` is the internal ID that is the one that needs to be used for other methods.\
This ID can be retrieved on creation or by searching the scan as shown in search examples.

```python
scan_id = sessus.search_scans(name=scan_name, after=scan_date)[0]["id"]
```


You can then retrieve the status of the scan by calling the `get_scan_status` method:

```python
scan_status = nessus.get_scan_status(scan_id)
```

You can also retrieve the reports of the scan once finished by calling the `get_scan_reports` method:

```python
scan_reports = nessus.get_scan_reports(scan_id)
```

You can search for scans by name or date by calling the `search_scans` method:

```python
scan_name = "My Scan"
scan_date = "2022-01-01_00:00:00"

scan_indices = nessus.search_scans(name=scan_name, after=scan_date)
```

You can then retrieve the status and reports of the matching scans by calling the `get_status_by_name` and `get_reports_by_name` methods:

```python
scan_status = nessus.get_status_by_name(scan_name)
scan_reports = nessus.get_reports_by_name(scan_name)
```

For more information on the available methods and their parameters, please refer to the docstrings in the `py_nessus.py` file.

## License

PyNessusPro is licensed under the GNU GENERAL PUBLIC LICENSE Version 2. See the `LICENSE` file for more information.
