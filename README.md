# Sindion Technical Task
This is a DRF API for Sindion technocal task, in this project we used JWT for authenctication, also used celery with redis as a broker to send emails in the balck ground and used mailhog to test sending emails in the development environment.

To run the project first clone the repo and then create vertualenv to run the project inside, after that install all the dependencies required for the project:

    pip install -r requirements.txt

after that make sure that redis serives in active and runnig on port **6379** so emails could be sent also make suer MailHog is active and runnig on port **1025** to test that emails is actually sent.

then you can run celery worker

    python -m celery -A SindionTask  worker -l info

after that you run the django project with:
    
    python manage.py runserver

and now all endpoints can be tested.

## API Endpoints 

    api/login/
    
    when user privides the correct username and password, they'll be issued a jwt token which can be used in authorization

-

    api/token/refresh/

    when user provides the refresh token they'll be issued a new access token

-
    
    api/logout/

    when user provides the refresh token, it'll be blacklisted and could never be used again

-

    api/change-password/<int:pk>/

    only the profile owner can acess this end point if needed to chaneg password, old password and the new one with confirmation should be provided to the end point to update the password

-
    
    api/request-reset-password/

    when the user provides his email to this endpoint, if the email is registered with account they will be sent and email with ling to reset their password

-   

    api/reset-password/

    this endpoint is the one sent to users by email to reset password, user should provied and new password with confirmation to update their password

-

    api/employees/

    lists all the employees
-
  
    api/clients/

    lists all the clients

- 
    api/user/<int:pk>/

    gets the details of the specified user

-

    api/user/delete/<int:pk>/

    only for the super user this endpoint will delete a specified user