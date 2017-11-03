# ASP.NET Core 2.0 Azure AD authentication example

This sample application is built on the 2.0 bits to test authentication via Azure AD.

To run it, you'll need to register an application in Azure AD, and fill out the client id and authority either in
appsettings.json or user secrets. You will also need to add a client secret (in user secrets preferrably).

You must also add permissions for the app to the Microsoft Graph API:

1. Find your app in the Azure AD blade's App Registrations tab in Azure Portal
1. Go to Required permissions
1. Click Add
1. Choose *Microsoft Graph* as the API
1. Select *Sign in and read user profile*, *View users' basic profile*, and *View users' email address* under *Delegated permissions*
1. Click Select and Done
