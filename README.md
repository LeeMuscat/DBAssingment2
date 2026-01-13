# DBAssingment2

For framework FastApi was using (python)
For Server Uvicorn
Database MongoDb
Enviorment Variables are stored in .env file
Api Testing done using FastAPI Swagger ui and postman

For runningg api locally
i created a python virtual enviroment installed dependencies stored MongoDb connection in .env as MONGO_URI
started a server using uvicorn and accessed the api using http://127.0.0.1:8000/docs

Database setup was done on MongoDB atlas/Compass
Databasename leeMuscatDB
Collections: events,attendees,venues,booking,media
for injection atttacks middleware was implemented that scans json requests and blocks suspicious inputted patters
