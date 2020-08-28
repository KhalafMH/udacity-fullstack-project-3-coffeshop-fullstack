# Coffee Shop FullStack API
This is my implementation of the Coffee Shop FullStack API project from the Udacity Fullstack Web Developer Nanodegree.


## Running the App
Running the app requires starting the backend server and the frontend server.

#### Starting the Backend Server 
##### Locally
To start the backend server you will need to have Python 3.8 installed.

Open a terminal and navigate to the `backend` directory and do the following steps:

* Intall the dependencies:
```shell script
pip install -r requirements.txt
```
* Start the app server:
```shell script
FLASK_APP=src/api.py flask run
```
* If all went well then the server will be running at `localhost:5000`

##### With Docker
To start the backend server using Docker follow the steps:

* Build the Docker image:
```shell script
docker build . -t coffeeshop-fullstack:SNAPSHOT
```
* Run the Docker image:
```shell script
docker run -it --rm --name coffeeshop -p 5000:5000 coffeeshop-fullstack:SNAPSHOT
```
* If all went well then the server will be running at `localhost:5000`

#### Starting the Frontend Server
To start the frontend server you will need to have NodeJS 10 and `npm` installed. open a terminal and navigate to the 
`frontend` directory and execute the following commands:

* Install the dependencies:
```shell script
npm install
```
* Start the frontend server:
```shell script
npm start
```
Now you should be able to access the app at the URL `http://localhost:4200`.


## API Reference
The API documentation for this app is hosted at the link:

[https://documenter.getpostman.com/view/12466232/TVCb4VbS]()