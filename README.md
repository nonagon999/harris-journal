# Harris Memorial College Journal Management System

A web-based journal management system for Harris Memorial College.

## Features

- User authentication and authorization
- Journal upload and management
- Profile management
- Search and filter functionality
- Citation tracking
- View and download statistics

## Prerequisites

- Node.js >= 14.0.0
- MongoDB Atlas account
- Railway.app account (for deployment)

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
NODE_ENV=production
PORT=3000
MONGODB_URI=your_mongodb_atlas_uri
BASE_URL=your_railway_app_url
EMAIL_USER=your_email
EMAIL_PASS=your_email_password
GOOGLE_CLIENT_ID=your_google_client_id
```

## Deployment Steps

1. Install dependencies:
   ```bash
   npm install
   ```

2. Deploy to Railway:
   - Create a new project on Railway.app
   - Connect your GitHub repository
   - Add the following environment variables in Railway:
     - NODE_ENV=production
     - MONGODB_URI=your_mongodb_atlas_uri
     - BASE_URL=your_railway_app_url
     - EMAIL_USER=your_email
     - EMAIL_PASS=your_email_password
     - GOOGLE_CLIENT_ID=your_google_client_id

3. Railway will automatically deploy your application when you push to the main branch.

## Local Development

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd harris-journal
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file with development settings:
   ```env
   NODE_ENV=development
   PORT=3000
   MONGODB_URI=mongodb://127.0.0.1:27017/harris_journal
   BASE_URL=http://localhost:3000
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

## Security Considerations

- Keep your environment variables secure
- Regularly update dependencies
- Use HTTPS in production
- Implement rate limiting
- Enable MongoDB Atlas security features
- Regular backups of the database

## License

This project is licensed under the MIT License. 