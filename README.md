# ASP.NET Core 2.1 Azure AD authentication example

This sample application is built on ASP.NET Core 2.1 to test authentication via Azure AD.

## Pre-requisites

You will need a development environment capable of running an ASP.NET Core 2.1 application.

Windows users can install [Visual Studio 2017](https://www.visualstudio.com/downloads/) with the **ASP.NET and web development workload**.

Users on Windows, Mac, or Linux can download the [.NET Core SDK](https://www.microsoft.com/net/download) and use any editor that works best.
[Visual Studio Code](https://code.visualstudio.com/) is pretty good.

## Setup instructions

To run the app locally, you'll need to register an application in Azure AD.

How to register the app:

1. Go to [https://portal.azure.com](https://portal.azure.com)
1. Find *Azure Active Directory* on the left or from under *All services*
1. Go to *App registrations*
1. Click on *New application registration*
1. Give the app a name, e.g. **ASP.NET Core 2 Azure AD Test**
1. Make sure the application type is **Web app/API**
1. Set sign-on URL to **http://localhost:5000/Account/SignIn**
1. Click **Create**

Getting client id, setting reply URL, and generating client secret:

1. After creation, open the app
1. Copy the **Application ID**, and put it somewhere, this is also called the Client ID
1. Click **Settings** and then **Reply URLs**
1. Add **https://localhost:5000/signin-oidc** to the list and save it
1. Go to **Keys**
1. In the *Passwords* section, put some description for the key, select the expiry, and hit **Save**
1. Copy the key value somewhere, this is your client secret (keep it secret)

Adding permissions for Microsoft Graph API:

1. Find your app in the Azure AD blade's App Registrations tab in Azure Portal
1. Go to Required permissions
1. Click Add
1. Choose *Microsoft Graph* as the API
1. Select *Sign in and read user profile*, *View users' basic profile*, and *View users' email address* under *Delegated permissions*
1. Click Select and Done

Getting the authority URL:

1. Go back to the App registrations list
1. Click **Endpoints**
1. Copy the **OAuth 2.0 Authorization Endpoint** value
1. Remove the */oauth2/authorize* part from the URL, the result is your *Authority*

Fill the values in settings:

1. Open the solution in Visual Studio
1. Set client id and authority in appsettings.json
1. Right-click on the project and click **Manage user secrets**
1. Add the client secret here. Example below:

```json
{
    "Authentication":{
        "ClientSecret": "your-client-secret....."
    }
}
```

The main reason to put the client secret there is to make sure it is not accidentally put into version control.
This is not absolute advice and you must make the decision how to store configurations for your app.
