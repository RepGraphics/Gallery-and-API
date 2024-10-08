# Gallery-and-API
An API with Discord OAuth Login to access a Gallery area (Per user) and re-roll their own API Access Token.

- You can easily add more API Endpoints in ``index.js``!
- The API has a low resource usage in it's current state, as you add more endpoints or have more users this can change.
- If you are wanting to host the api on a domain, you can use NGINX Proxy to pass the IP:Port through to a Domain.
- All Endpoints require an API token, except for the status endpoint.

### Javascript/Node.JS
The API/Gallery is ran using Node.JS, using express, passport, mongoDB for Databases and more.

### Features
- Ability to link sign-in with MongoDB, so only authorised discord userID's can sign in to the API.
- Per user Gallery/Uploads.
- API Documentation Page.
- Gallery Images contain share links for easy Image Sharing or Usage externally.
- Storage - All images are stored under ``/public/images/${userID}/${filename}``
- .env is populated with example data, to help with configuration.
- Supports .EJS out of the box, for easy Integrations.

### NPM Packages Required
    "axios": "^1.7.7",
    "bcrypt": "^5.1.1",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "crypto": "^1.0.1",
    "dotenv": "^16.4.5",
    "ejs": "^3.1.10",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "express-session": "^1.18.0",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "mongodb": "^6.8.0",
    "multer": "^1.4.5-lts.1",
    "passport": "^0.7.0",
    "passport-discord": "^0.1.4",
    "passport-oauth2": "^1.8.0"

![Screenshot 2024-09-24 151905](https://github.com/user-attachments/assets/a6c22e54-62b0-45b8-bc8c-7d1ebbae7a8b)
![Screenshot 2024-09-24 151854](https://github.com/user-attachments/assets/9b7d262f-bc91-475b-9456-de12c44a1bba)
![Screenshot 2024-09-24 151845](https://github.com/user-attachments/assets/f24e36d0-99ae-4a29-80d3-4ec820449f5e)
![Screenshot 2024-09-24 151835](https://github.com/user-attachments/assets/e29b5b42-be08-496d-9b66-c45eed310c6e)
