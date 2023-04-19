
# Flask User Authentication App

## Run
Run the app for development:
```commandline
docker-compose -f docker-compose-dev.yml up --build
```
Run the app for production:
```commandline
docker-compose up --build
```
### Features
The app allows:
- User signup, login, change user password
- Check user login sessions history (date logged in, IP address, User Agent)
- Store User credentials in PostgreSQL database       
- Create Access & Refresh Tokens stored in Redis 
- Add or update user roles by Admin

## Changelog
April 7, 2023:
- Add User Registration
- Add User Roles
- Add Open API Spec
  - Add `docker-compose.yml` for easy deployment on a server

April 18, 2023:
- Refactor API Spec
- Refactor App Structure

April 19, 2023:
- Add functional tests

## Maintainers 
Aleksei Stepanov: https://github.com/microseis 

## API Spec
http://localhost:8000/apidoc/swagger/

## Console Commands
-Create Superuser
```commandline
 flask --app src/main.py createsuperuser --admin_password 12345 
```
-Create Database Tables
```commandline
 flask --app src/main.py createdbtables  
```
## Run Tests
Go to tests directory and type `pytest` command in console to run all tests
