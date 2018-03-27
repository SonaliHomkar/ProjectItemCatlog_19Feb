import os

# This file is used to store configuration path

# This is used to store database path
DBPATH = os.path.join(os.path.abspath(os.path.dirname(__file__)),'ItemCatlog.db')

# This is used to store client_secrets.json file path 
CLIENT_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)),'client_secrets.json')

