
# Flask User Authentication App

## Run
Run the app for development:
```commandline
docker-compose -f docker-compose-dev.yml up --build
```
### Features
The app allows:
- User signup, login, change user password     
- Store User credentials in PostgreSQL database       
- Access & Refresh Tokens  
- 
## Changelog
April 7, 2023:
- Add User Registration
- Add User Roles
- Add Open API Spec
- Add `docker-compose.yml` for easy deployment on a server
April 18, 2023:
- Refactor API Spec
- Refactor App Structure

## Maintainers 
Aleksei Stepanov: https://github.com/microseis

## API Spec
http://127.0.0.1:8000/api/openapi

## Console Commands
-Create Superuser
```commandline
 flask --app main.py createsuperuser --admin_password 12345 
```
-Create Database Tables
```commandline
 flask --app main.py create_db_tables  
```