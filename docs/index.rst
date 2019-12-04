.. gatorchat documentation master file, created by
   sphinx-quickstart on Tue Dec  3 17:41:28 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to gatorchat's documentation!
=====================================

*****
Overview
*****
GatorChat is an encrypted peer to peer chat client. It is built using a client and Django server that handles key distribution and authentication. To start 
browsing the documentation head over to the :ref:`modindex` page. Ideally a group would run their own server rather than have a single 
public directory. The passphrases for profile's A and B are both **hello**. 

Testing
########
This project was built with python 3.7.5. To install the necessary requirements run *pip install requirements.txt* from the home directory. Included is the virtual environment
used to build this project, it is unlikely to work on other machines so create your own using *virtualenv*. It is always best to create a virtual enviroment before installing
the necessary packages.  

Technologies used:
    * ZeroMQ Asynchronous messaging library
    * Python's Crpyto library
    * Django/DRF for the server
    * Wide mouthed frog protocol

Steps to run:
    1. Start the django server by running *python manage.py runserver* from the *server/chat_server/* directory
    2. Launch your clients by running *python main.py* from the *client/* directory and sign in or create a profile
    3. With one host select *Host a new chat* from the main menu and enter a desired password
    4. With another host select *Create a new chat* from the main menu and enter the username of the other host and the password
    5. Start chatting!
    6. Type 'exit()' to disconnect from the chat.

Testing
########
To run the test code run *python tests.py* from the *client/* directory. Currently these tests
check the symmetric and asymmetric encryption capabilities as well as the messsage signing function.

Extra Information
########
Currently the client and server are configured to run from local host due to the port forwarding requirements of running it on UF's network. 
To change that you will need to change the client code to reflect the ip address of the server as well as configure your router for port forwarding.

.. toctree::
   :maxdepth: 2

   :caption: Contents:

    main.rst
    cryptochat.rst
    encryption_manager.rst
    messaging.rst
    profile.rst


Indices and tables
==================

* :ref:`modindex`
* :ref:`search`

