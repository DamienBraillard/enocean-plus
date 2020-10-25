# EnOcean Plus
An improved library for accessing the EnOcean network from Python through the USB3xx dongles.

## Features and goals
- [ ] Supports asyncio
- [ ] Encoding and decoding of telegrams for all defined EEP
- [ ] Handling of UTE teaching
- [ ] Supports fetching info about the dongle and setting up the dongle
- [ ] Fully unit tested

This is work in progress, checkboxes below will be ticked as the development progresses...

## Development
### Setting up the development environment
From the root of the repository:
1. Create a Python 3.7+ virtual env
    ```shell script
    $> virtualenv -p python3 venv
    ```
2. Activate the virtual environment
    ```shell script
    source venv/bin/activate
    ```
3. Restore the required python packages from the `requirements.txt` file
    ```shell script
    pip install -r requirements.txt
    ```

### Running the unit tests
From the activated virtual environment, run:
```shell script
pytest
```

## Installation
TBD


