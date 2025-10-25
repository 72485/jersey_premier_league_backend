import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:postgres/postgres.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:jersey_premier_league_backend/models/user.dart'; // Assuming this is correct


// A secret key for signing JWTs. In a real production app, load this securely
// from an environment variable and make it much more complex.
const String _jwtSecret = 'supersecretjwtkeyforjplapp';

/// Service class responsible for handling all authentication-related logic
/// and database interactions for the backend.
class BackendAuthService {
  // This private field holds the live connection to the PostgreSQL database.
  final PostgreSQLConnection _dbConnection;

  BackendAuthService(this._dbConnection);

  // --- PRIVATE HELPER FUNCTIONS ---

  /// Helper to create a standardized JSON response.
  Response _jsonResponse(int statusCode, Map<String, dynamic> body) {
    return Response(
      statusCode,
      body: json.encode(body),
      headers: {'Content-Type': 'application/json'},
    );
  }

  /// Extracts the JWT from the 'Authorization: Bearer <token>' header.
  String? _extractToken(Request request) {
    final authHeader = request.headers['authorization'];
    if (authHeader != null && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return null;
  }

  // ⚡ REQUIRED FIX: Adds the missing _verifyToken helper function
  // which is used by changePasswordHandler and updateProfileHandler.
  JWT _verifyToken(String token) {
    try {
      return JWT.verify(token, SecretKey(_jwtSecret));
    } on JWTExpiredException {
      // Re-throw the specific exception to be caught by the handler
      throw JWTExpiredException();
    } on JWTException {
      // Re-throw a generic JWT exception
      throw JWTException('Invalid token');
    }
  }


  // --- API HANDLERS ---

  /// Handles POST /api/register
  /// Creates a new user in the database.
  Future<Response> registerHandler(Request request) async {
    try {
      final body = json.decode(await request.readAsString());
      final name = body['name'] as String?;
      final emailInput = body['email'] as String?; // Original email input
      final password = body['password'] as String?;

      if (name == null || emailInput == null || password == null) {
        return _jsonResponse(400, {'error': 'Missing required fields: name, email, password'});
      }

      // Standardize to lowercase
      final email = emailInput.toLowerCase();

      // Check if user already exists (Case-Insensitive Check)
      final existingUser = await _dbConnection.query(
        "SELECT id FROM users WHERE LOWER(email) = @email LIMIT 1",
        substitutionValues: {'email': email},
      );

      if (existingUser.isNotEmpty) {
        return _jsonResponse(409, {'error': 'User with this email already exists'});
      }

      // Hash the password for secure storage
      final hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());

      // Insert new user into the database. Storing the standardized (lowercase) email.
      final result = await _dbConnection.query(
        "INSERT INTO users (name, email, password_hash) VALUES (@name, @email, @hash) RETURNING id, name, email, fpl_team_id",
        substitutionValues: {
          'name': name,
          'email': email, // Save the lowercase version
          'hash': hashedPassword,
        },
      );

      // Send back the User object and a JWT token
      final newUserRow = result.first.toColumnMap();
      final user = BackendUser.fromPostgreSQL(newUserRow);

      // Generate a JWT
      final jwt = JWT({'id': user.id, 'email': user.email});
      final token = jwt.sign(SecretKey(_jwtSecret), expiresIn: Duration(days: 7));

      // Combine user data and the token for the client response
      final userWithToken = user.toJson()..['token'] = token;

      return _jsonResponse(201, userWithToken);
    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Registration: $e');
      return _jsonResponse(500, {'error': 'Database error: Could not register user.'});
    } catch (e) {
      print('Registration Error: $e');
      return _jsonResponse(500, {'error': 'An internal server error occurred'});
    }
  }

  /// Handles POST /api/login
  /// Authenticates a user and returns their data along with a JWT.
  Future<Response> loginHandler(Request request) async {
    try {
      final body = json.decode(await request.readAsString());
      final emailInput = body['email'] as String?; // Original email input
      final password = body['password'] as String?;

      if (emailInput == null || password == null) {
        return _jsonResponse(400, {'error': 'Missing required fields: email, password'});
      }

      // Standardize to lowercase
      final email = emailInput.toLowerCase();

      // Query database using LOWER() for case-insensitive matching
      final result = await _dbConnection.query(
        "SELECT id, name, email, password_hash, fpl_team_id FROM users WHERE LOWER(email) = @email LIMIT 1",
        substitutionValues: {'email': email},
      );

      if (result.isEmpty) {
        return _jsonResponse(401, {'error': 'Invalid email or password'});
      }

      // Get the first (and only) row
      final userRow = result.first.toColumnMap();
      final storedHash = userRow['password_hash'] as String;

      // Verify the provided password against the stored hash
      if (!BCrypt.checkpw(password, storedHash)) {
        return _jsonResponse(401, {'error': 'Invalid email or password'});
      }

      // Generate a JWT
      final user = BackendUser.fromPostgreSQL(userRow);
      // The JWT payload contains minimal data to identify the user
      final jwt = JWT({'id': user.id, 'email': user.email});
      final token = jwt.sign(SecretKey(_jwtSecret), expiresIn: Duration(days: 7));

      // Combine user data and the token for the client response
      final userWithToken = user.toJson()..['token'] = token;

      return _jsonResponse(200, userWithToken);
    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Login: $e');
      return _jsonResponse(500, {'error': 'Database error during login.'});
    } catch (e) {
      print('Login Error: $e');
      return _jsonResponse(500, {'error': 'An internal server error occurred'});
    }
  }

  /// Handles POST /api/profile/update
  /// A protected route that updates the user's FPL Team ID and/or name.
  Future<Response> updateProfileHandler(Request request) async {
    try {
      final token = _extractToken(request);
      if (token == null) {
        return _jsonResponse(401, {'error': 'Unauthorized: No token provided'});
      }

      // Verify the JWT to authenticate the user
      final jwt = _verifyToken(token); // Uses the new _verifyToken helper
      final payload = jwt.payload as Map<String, dynamic>;

      // The ID from the JWT payload is the user's INTEGER ID (from SERIAL).
      final userId = payload['id'] as int;

      final body = json.decode(await request.readAsString());
      final fplTeamId = body['fpl_team_ID'] as String?;
      final name = body['name'] as String?;

      if (fplTeamId == null && name == null) {
        return _jsonResponse(400, {'error': 'Missing required fields: fpl_team_ID or name'});
      }

      // Start building the update query parts
      final List<String> setClauses = [];
      // Use the correctly typed INTEGER userId
      final Map<String, dynamic> substitutionValues = {'userId': userId};

      if (fplTeamId != null) {
        setClauses.add("fpl_team_id = @fplTeamId");
        substitutionValues['fplTeamId'] = fplTeamId;
      }
      if (name != null) {
        setClauses.add("name = @name");
        substitutionValues['name'] = name;
      }

      // Execute the update
      final updateSql = "UPDATE users SET ${setClauses.join(', ')} WHERE id = @userId";

      final result = await _dbConnection.execute(
        updateSql,
        substitutionValues: substitutionValues,
      );

      if (result == 0) {
        return _jsonResponse(404, {'error': 'User not found'});
      }

      // Return the updated fields so the client can confirm the change
      final Map<String, dynamic> responseBody = {'message': 'Profile updated successfully'};
      if (fplTeamId != null) {
        responseBody['fpl_team_ID'] = fplTeamId;
      }
      if (name != null) {
        responseBody['name'] = name;
      }

      return _jsonResponse(200, responseBody);

    } on JWTExpiredException {
      return _jsonResponse(401, {'error': 'Unauthorized: Token has expired'});
    } on JWTException catch (e) {
      // Handles invalid signature, invalid claims, etc.
      return _jsonResponse(401, {'error': 'Unauthorized: Invalid token (${e.message})'});
    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Update: $e');
      return _jsonResponse(500, {'error': 'Database error during profile update.'});
    } catch (e) {
      print('Profile Update Error: $e');
      return _jsonResponse(500, {'error': 'An internal server error occurred'});
    }
  }

  /// Handles POST /api/password/change
  /// A protected route that allows a user to update their password.
  Future<Response> changePasswordHandler(Request request) async {
    final token = _extractToken(request);
    if (token == null) {
      return _jsonResponse(401, {'error': 'Unauthorized: Missing token'});
    }

    try {
      // 1. Verify token and extract user ID
      final jwt = _verifyToken(token);
      final userId = jwt.payload['id'] as int;

      final body = json.decode(await request.readAsString());
      final currentPassword = body['current_password'] as String?;
      final newPassword = body['new_password'] as String?;

      if (currentPassword == null || newPassword == null) {
        return _jsonResponse(400, {'error': 'Missing current password or new password'});
      }
      if (newPassword.length < 6) {
        return _jsonResponse(400, {'error': 'New password must be at least 6 characters'});
      }

      // 2. Fetch user to verify current password
      final result = await _dbConnection.query(
        'SELECT password_hash FROM users WHERE id = @id',
        substitutionValues: {'id': userId},
      );

      if (result.isEmpty) {
        return _jsonResponse(404, {'error': 'User not found'});
      }

      final storedHash = result.first[0] as String;

      // 3. Verify current password
      if (!BCrypt.checkpw(currentPassword, storedHash)) {
        // Correctly uses 401 for an authentication failure
        return _jsonResponse(401, {'error': 'Incorrect current password'});
      }

      // 4. Hash the new password
      final newPasswordHash = BCrypt.hashpw(newPassword, BCrypt.gensalt());

      // 5. Update the password hash in the database
      await _dbConnection.execute(
        'UPDATE users SET password_hash = @hash WHERE id = @id',
        substitutionValues: {
          'hash': newPasswordHash,
          'id': userId,
        },
      );

      return _jsonResponse(200, {'message': 'Password changed successfully'});

    } on JWTExpiredException {
      return _jsonResponse(401, {'error': 'Unauthorized: Token has expired'});
    } on JWTException catch (e) {
      return _jsonResponse(401, {'error': 'Unauthorized: Invalid token (${e.message})'});
    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Password Change: $e');
      return _jsonResponse(500, {'error': 'Server error during password update'});
    } catch (e) {
      print('Password Change Error: $e');
      return _jsonResponse(500, {'error': 'An unknown server error occurred'});
    }
  }
}