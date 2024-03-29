# GoogleAuth
Template for using Google Authentication, using JavaScript, Node, Express, Passport, and MongoDB.

## Setting Up App

### 1. Install Dependencies
Use `npm install` to install all required node packages in package.json.

### 2. Configure Google Credentials
Go to [Google Cloud Console](https://console.cloud.google.com/) and either create a new project or select an existing one. 
Then navigate to the credentials page and access your OAuth clientID and OAuth secret.

### 3. Set Environment Variables
Create a `.env file` in the root of your project and add the following information:
<pre>
CLIENT_ID=YOUR_GOOGLE_CLIENT_ID
CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET
</pre>

### 4. Run application
Use `node app.js` or `nodemon app.js` to run your project.

### 5. View Application
The app runs on port 3000 by default. Go to localhost/3000 to view the app.
