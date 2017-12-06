# globus-id-explorer
This is a Web app that allows anyone to explore their Globus identity information. It is intended 
to be deployed on a public Web server so that one can connect to it using a Web browser, login, 
see the data that Globus's Auth API provides to the app, and logout. The purpose of the app is to 
show Web developers what the identity information returned from the Auth API looks like so that 
they can then write their own apps that use the Auth API.

This app is meant to be deployed as a [WSGI application](https://wsgi.readthedocs.io/en/latest/) 
using a standard Web server (e.g., Apache) as a host. The server is responsible for providing a 
secure HTTP (HTTPS) environment in which the app can run. The Web server administrator must 
enable the WSGI module and add a server configuration module that references the location where 
this app has been installed. Instructions are below, and this repository includes sample 
configuration files.

## Prerequisites
Before installing the app, you must have the following already available on your Web server system.

1. A Web server! The examples provided here are for the Apache Web server, available on Linux systems.
2. A WSGI module for your server. Check your server documentation.
3. A Python installation. Python 3 is preferred, and the examples below assume it.
4. The ``virtualenv`` and ``pip`` Python tools.

## Installation
The first installation step is to install the app files in a location where your web server can
access them. Assuming that your Web server uses the /var/www/html directory as its document 
root, you might want to create /var/www/apps as the root for your Web apps.  Create the directory
and set permissions so you can put things there.
```
% sudo su
[sudo] password for liming: 
# cd /var/www
# mkdir apps
# chown liming:liming apps
# exit
```
Now clone the git repository in the new directory to make a local copy of everything.
```
% cd /var/www/apps
% git clone http://github.com/lliming/globus-id-explorer.git
[git does its thing]
% cd globus-id-explorer
% ls
auth_example.conf  auth_example.py  auth_example.wsgi  flask_example.py  flask_example.wsgi  hello.wsgi  requirements.txt
% 
```
This will create a subdirectory called globus-id-explorer with the files in it.

Next, create a Python virtual environment and install the required Python packages in it.
```
% virtualenv -p python3 venv
[virtualenv does its thing]
% source venv/bin/activate
(venv) % pip install -r requirements.txt
[pip does its thing]
(venv) % deactivate
% 
```
