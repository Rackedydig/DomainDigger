@echo off

REM Create a new Python 3 virtual environment
python3 -m venv DomainDigger

REM Activate the environment
CALL DomainDigger\Scripts\activate.bat

REM Install the necessary packages
pip install pandas
pip install requests
pip install python-dotenv

REM Save the list of installed packages into a requirements file
pip freeze > requirements.txt