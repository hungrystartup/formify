# Formify Backend

A robust Node.js backend API for handling form submissions with authentication, rate limiting, and message management.

## Features

- 🔐 **JWT Authentication** - Secure user authentication with cookies
- 📝 **Form Submission API** - Public endpoint for form submissions via API key
- 🛡️ **Rate Limiting** - Built-in rate limiting with Redis
- 🍪 **CORS Support** - Cross-origin requests with cookie support
- 📊 **Message Management** - View, delete, and track form submissions
- 🔑 **API Key System** - Secure API key generation and management
- 📈 **Usage Tracking** - Monitor message limits and usage statistics
- 🧹 **Input Sanitization** - XSS protection with HTML sanitization

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MySQL
- **Cache**: Redis
- **Authentication**: JWT
- **Security**: bcrypt, sanitize-html
- **Rate Limiting**: rate-limiter-flexible

## Prerequisites

- Node.js (v14 or higher)
- MySQL database
- Redis server (optional, for rate limiting)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd formify
   ```

2. **Install dependencies**
   ```bash
   npm install
   cd src && npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   PORT=3000
   DATABASE_HOST=localhost
   DATABASE_USER=your_user
   DATABASE_PASSWORD=your_password
   DATABASE_NAME=your_database
   JWT_SECRET=your_jwt_secret
   FRONTEND_URL=https://your-frontend.com
   REDIS_URL=redis://localhost:6379
   ```

4. **Set up the database**
   ```bash
   node src/db.js
   ```

## Usage

### Start the server
```bash
npm start
```

The server will start on the configured port (default: 3000).

### Development

**Format code:**
```bash
npm run format
```

**Check formatting:**
```bash
npm run format:check
```

## API Endpoints

### Authentication

#### POST `/signup`
Register a new user account.
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securepassword"
}
```

#### POST `/login`
Authenticate user and get JWT token.
```json
{
  "email": "john@example.com",
  "password": "securepassword"
}
```

#### POST `/logout`
Clear authentication cookies.

#### GET `/authorize`
Verify JWT token (protected route).

### API Key Management

#### GET `/apikey`
Get user's API key (protected route).

### Form Submission

#### POST `/v1/submit/:apikey`
Submit a form using API key (public endpoint).
```json
{
  "email": "user@example.com",
  "message": "Form message content",
  "_redirect": "https://example.com/thank-you" // optional
}
```

### Message Management

#### GET `/api/messages`
Get recent messages (protected route).

#### GET `/api/message`
Get paginated messages (protected route).
```
/api/message?limit=10&offset=0
```

#### GET `/delete`
Delete a message (premium users only).
```
/delete?id=message_id
```

### Usage Statistics

#### GET `/api/total`
Get total messages sent (protected route).

#### GET `/api/current`
Get current message count (protected route).

#### GET `/api/limit`
Get message limit (protected route).

#### GET `/api/status`
Get user status (protected route).

#### GET `/api/message-stats`
Get message statistics (protected route).

#### GET `/message-progress`
Get message progress (protected route).

### Utility

#### GET `/ping`
Health check endpoint.

#### GET `/username`
Get username (protected route).

## Database Schema

### Users Table
- `id` - Primary key
- `username` - User's display name
- `email` - User's email (unique)
- `password` - Hashed password
- `api_key` - Generated API key
- `max_message` - Message limit
- `current_message` - Current message count
- `total_messages` - Total messages sent
- `status` - User status (0: free, 1: premium)

### Messages Table
- `id` - Primary key
- `user_id` - Foreign key to users
- `content` - Message content
- `submitted_email` - Email from form submission
- `site_url` - Referrer URL
- `received_at` - Timestamp

## Security Features

- **JWT Authentication** with secure cookie settings
- **Password Hashing** using bcrypt
- **Input Sanitization** to prevent XSS attacks
- **Rate Limiting** to prevent abuse
- **CORS Configuration** for cross-origin requests
- **SQL Injection Protection** using parameterized queries

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | 3000 |
| `DATABASE_HOST` | MySQL host | localhost |
| `DATABASE_USER` | MySQL username | - |
| `DATABASE_PASSWORD` | MySQL password | - |
| `DATABASE_NAME` | MySQL database name | - |
| `JWT_SECRET` | JWT signing secret | - |
| `FRONTEND_URL` | Frontend domain | - |
| `REDIS_URL` | Redis connection URL | redis://localhost:6379 |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `npm run format` to format code
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For support and questions, please open an issue in the repository.
