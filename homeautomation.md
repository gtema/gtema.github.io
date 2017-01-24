# HomeAutomatization #

## Intro
My [HomeAutomation project](https://bitbucket.org/goncharovartem/homeautomation) is an attempt to optimize some of 
the household activities and their efficiency. 
One of the most noticable examples for that is to keep track of 
groceries and household products to avoid their disposal or sudden lack. 
Sometimes you come from the shop and figure out that you have already few packages of flour. 
On the other hand you start coocking and figure out, that you have no milk. 
In order to solve this problem and potentially some others this project was created.

There is no idea to make this project public or to provide/guarantee any support to anybody, who would like to use it. 
However it is not in any way prohibited for anyone to use it.

## Quick summary ##

The project consists currently from two independend modules: API and the web UI.

* API is a simple set of REST CRUD services to provide access to the database. It is based on the python Flask framework.
* Web UI is based on the Redux + React combination. Development is based on the Node.JS, which is, however, unlikely to be used in "production".
* DB is not considered as a module. Feel free to use any database of your choise with access from Python.

The basic UML diagrams for the project can be viewed from Model.xmi file (created using Umbrello). They are not 100% identical with the state of the project due to the early development phase.

### Version

Heavy development stage, therefore just 0.0.2
Usually I do commits while switching between dev stations, so not every commit is considered as end of work.

So far API capabilities of login are not used. After project becomes usefull - login will be enabled. Basically infrastructure is already there.


### How do I get set up? ###

* Use of docker-compose (preferred)

Issue docker-compose up and you are set to go. Local directories are mounted into the images,
so that local changes affect containers immediately without redeployment.

* Use of local python and npm

Use script setup.sh in order to setup python virtual environment and npm modules.
After that use server/start_server.sh script to start api and web/npm start to start node.js


### Configuration ###

Api configuration is present under the server/{config.py,instance/config.py}
Node requires REACT_APP_API_HOST environment variable to point to the API (default 127.0.0.1:5000/api/v0/stock), REACT_APP_API_PATH and REACT_API_KEY

### Dependencies ###

Quite a few, listed per component correspondingly (server/requirements.txt and web/package.json)

### Database configuration ###

Up to now a local SQLite DB is used (app.SQLite) internally. Surely not a production way. API contains init.py script, which creates the DB schema according to the configured connection and populates it with my "development" data. Feel free to modify it for your needs.

### How to run tests ###

`cd web && npm test`

`cd server && python test.py` (do not forget you virtualenv)

### Security ###

Thought currently no users are used (identification per API key), the DB schema supports users. 
However no other authorization is implemented so far (this is namely one of the Flask "weak-sides"). 
In my case there is no public availability planned in the first time, so this has a lower priority. 
It's not that security has in general lower prio, just in the development phase it will be implemented later ;-)

Generally speaking even part of this repo should not be made available. 
It is a development version, so for your production:

* connect to real DB. Do NOT use build in app.SQLite, as API_KEY is alreay exposed to public.
* If you intend to use docker-compose modify it with an appropriate API_KEY or other security measures you have taken.

### Deployment instructions ###

I'm planning to run the project on the RaspberryPi V1. So most likely it would be deployed under mod_wsgi@apache application serving also compacted JS due to the performance lack. However there are multiple possibilities for deployment:
* docker containers (standalone containers, mixed container with mod_fsgi + compacted JS, docker-compose)
* Standalone apps: API (Flask server, any other Python web server, mod_fsgi) and Web (node.js, minimized JS on a static web werver)

The only rule for deployment: connect API with DB of your choice, configure Backend to give correct link to API from browsers.

### UML diagrams

comming soon. They are present in the repo, but later I will export them as images
