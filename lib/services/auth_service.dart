// lib/services/auth_service.dart (FINAL - Concurrency Safe with package:pool)

import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:postgres/postgres.dart';
import 'package:bcrypt/bcrypt.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:jersey_premier_league_backend/models/user.dart';
import 'package:http/http.dart' as http;
import 'dart:math';

import 'package:mailer/mailer.dart';
import 'package:mailer/smtp_server.dart';
import 'package:pool/pool.dart'; // 🔑 NEW: Import the Pool library


// A secret key for signing JWTs.
const String _jwtSecret = 'supersecretjwtkeyforjplapp';

// ... (EmailService class remains unchanged) ...
class EmailService {
  final SmtpServer _smtpServer;
  final String _senderEmail;

  EmailService({
    required String smtpHost,
    required int smtpPort,
    required String smtpUsername,
    required String smtpPassword,
    required bool smtpSsl,
    required String senderEmail,
  })  : _senderEmail = senderEmail,
        _smtpServer = SmtpServer(
          smtpHost,
          port: smtpPort,
          username: smtpUsername,
          password: smtpPassword,
          ssl: smtpSsl,
        );

  // ... (sendVerificationEmail function remains unchanged) ...
  Future<void> sendVerificationEmail({
    required String recipientEmail,
    required String verificationToken,
    required String serverHost,
  }) async {
    final verificationLink = 'http://$serverHost/api/verify?token=$verificationToken';

    print('LOG: Starting email send to $recipientEmail. Link: $verificationLink');

    final message = Message()
      ..from = Address(_senderEmail, 'JPL Support')
      ..recipients.add(recipientEmail)
      ..subject = 'Jersey Premier League - Account Verification'
      ..html = '''
        <p>Thank you for registering for the Jersey Premier League!</p>
        <p>Please click the link below to verify your email address:</p>
        <p><a href="$verificationLink">$verificationLink</a></p>
        <p>If you did not sign up for this account, please ignore this email.</p>
        <p>Best regards,<br>The JPL Team</p>
      ''';

    try {
      await send(message, _smtpServer);
      print('LOG: Message sent successfully to $recipientEmail!');

    } on MailerException catch (e) {
      print('!!! CRITICAL ERROR: Message not sent. MailerException details:');
      for (var p in e.problems) {
        print('Problem Code: ${p.code}, Message: ${p.msg}');
      }
      throw Exception('Failed to send verification email.');

    } catch (e, stackTrace) {
      print('!!! CRITICAL ERROR: Unexpected error sending email: $e');
      print('Stack Trace: $stackTrace');
      throw Exception('Failed to send verification email due to an unexpected error: $e');
    }
  }
}


/// Service class responsible for handling all authentication-related logic
class BackendAuthService {
  // 🔑 FIX: Store the single connection object
  final PostgreSQLConnection _dbConnection;
  // 🔑 FIX: Store the concurrency pool object
  final Pool _requestPool;
  final EmailService _emailService;
  final String _serverHost;

  // 🔑 FIX: Update constructor to accept both objects
  BackendAuthService(this._dbConnection, this._requestPool, this._emailService, this._serverHost);

  // --- Helper Functions ---
  String _generateVerificationToken() {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    final random = Random.secure();
    return List.generate(32, (index) => chars[random.nextInt(chars.length)]).join();
  }

  Response _jsonResponse(int statusCode, Map<String, dynamic> body) {
    return Response(
      statusCode,
      body: json.encode(body),
      headers: {'Content-Type': 'application/json'},
    );
  }

  String? _extractToken(Request request) {
    final authHeader = request.headers['authorization'];
    if (authHeader != null && authHeader.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }
    return null;
  }

  JWT _verifyToken(String token) {
    try {
      return JWT.verify(token, SecretKey(_jwtSecret));
    } on JWTExpiredException {
      throw JWTExpiredException();
    } on JWTException {
      throw JWTException('Invalid token');
    }
  }

  Future<Map<String, dynamic>?> _validateToken(Request request) async {
    final token = _extractToken(request);
    if (token == null) return null;

    try {
      final jwt = _verifyToken(token);
      if (jwt.payload is Map<String, dynamic>) {
        return jwt.payload as Map<String, dynamic>;
      }
      return null;
    } on JWTException {
      return null;
    }
  }


  // --- API HANDLERS ---

  /// Handles POST /api/register
  Future<Response> registerHandler(Request request) async {
    try {
      final bodyString = await request.readAsString();
      print('LOG: Register attempt received. Body: $bodyString');

      final body = json.decode(bodyString);
      final name = body['name'] as String?;
      final emailInput = body['email'] as String?;
      final password = body['password'] as String?;

      if (name == null || emailInput == null || password == null) {
        print('LOG: Registration failed - Missing required fields');
        return _jsonResponse(400, {'error': 'Missing required fields: name, email, password'});
      }

      final email = emailInput.toLowerCase();
      final hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt());
      final verificationToken = _generateVerificationToken();

      // 🔑 CRITICAL FIX: Wrap the entire DB operation in the request pool
      final result = await _requestPool.withResource(() async {

        // Use the persistent connection object inside the pool block
        return _dbConnection.transaction((ctx) async {

          // 1. Check for existing user
          final existingUser = await ctx.query(
            "SELECT id FROM users WHERE LOWER(email) = @email LIMIT 1",
            substitutionValues: {'email': email},
          );

          if (existingUser.isNotEmpty) {
            throw Exception('User with this email already exists');
          }

          // 2. Insert new user
          return ctx.query(
            "INSERT INTO users (name, email, password_hash, is_email_verified, verification_token) VALUES (@name, @email, @hash, FALSE, @token) RETURNING id, name, email, fpl_team_id, is_email_verified",
            substitutionValues: {
              'name': name,
              'email': email,
              'hash': hashedPassword,
              'token': verificationToken,
            },
          );
        });
      });
      print('LOG: User successfully inserted into database: $email');

      final newUserRow = result.first.toColumnMap();
      final user = BackendUser.fromPostgreSQL(newUserRow);

      // Send the actual email
      try {
        await _emailService.sendVerificationEmail(
          recipientEmail: user.email,
          verificationToken: verificationToken,
          serverHost: _serverHost,
        );
        print('LOG: Email service completed successfully for ${user.email}');
      } catch (e) {
        print('!!! FAILED TO SEND EMAIL: $e');
      }

      return _jsonResponse(201, user.toJson()..['message'] = 'User registered. Please check your email for verification.');

    } on PostgreSQLException catch (e) {
      print('!!! PostgreSQL Error during Registration: $e');
      return _jsonResponse(500, {'error': 'Database error: Could not register user.'});
    } catch (e) {
      // Handle the 'Email already exists' exception thrown inside the pool run block
      if (e.toString().contains('User with this email already exists')) {
        return _jsonResponse(409, {'error': 'User with this email already exists'});
      }
      print('!!! Registration Error (Unhandled): $e');
      return _jsonResponse(500, {'error': 'An internal server error occurred'});
    }
  }

  /// Handles POST /api/login
  Future<Response> loginHandler(Request request) async {
    try {
      final body = json.decode(await request.readAsString());
      final emailInput = body['email'] as String?;
      final password = body['password'] as String?;

      if (emailInput == null || password == null) {
        return _jsonResponse(400, {'error': 'Missing required fields: email, password'});
      }

      final email = emailInput.toLowerCase();

      // 🔑 CRITICAL FIX: Wrap the query in the request pool
      final result = await _requestPool.withResource(() async {
        return _dbConnection.query(
          "SELECT id, name, email, password_hash, fpl_team_id, is_email_verified FROM users WHERE LOWER(email) = @email LIMIT 1",
          substitutionValues: {'email': email},
        );
      });

      if (result.isEmpty) {
        return _jsonResponse(401, {'error': 'Invalid email or password'});
      }

      final userRow = result.first.toColumnMap();
      final storedHash = userRow['password_hash'] as String;

      if (!BCrypt.checkpw(password, storedHash)) {
        return _jsonResponse(401, {'error': 'Invalid email or password'});
      }

      final user = BackendUser.fromPostgreSQL(userRow);

      final jwt = JWT({'id': user.id, 'email': user.email, 'verified': user.isEmailVerified});
      final token = jwt.sign(SecretKey(_jwtSecret), expiresIn: Duration(days: 7));

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

  /// Handles GET /api/verify
  Future<Response> verifyEmailHandler(Request request) async {
    try {
      final queryParams = request.url.queryParameters;
      final token = queryParams['token'];

      if (token == null || token.isEmpty) {
        return Response.badRequest(body: 'Missing verification token');
      }

      // 🔑 CRITICAL FIX: Wrap the execute in the request pool
      final resultCount = await _requestPool.withResource(() async {
        return _dbConnection.execute(
          "UPDATE users SET is_email_verified = TRUE, verification_token = NULL WHERE verification_token = @token AND is_email_verified = FALSE",
          substitutionValues: {'token': token},
        );
      });

      if (resultCount == 0) {
        return Response.notFound('<h1>Verification Failed</h1><p>Invalid, expired, or already-used verification link.</p>', headers: {'Content-Type': 'text/html'});
      }

      return Response.ok('<h1>Success!</h1><p>Email verified successfully! You can now close this window and log in to the app.</p>', headers: {'Content-Type': 'text/html'});

    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Verification: $e');
      return _jsonResponse(500, {'error': 'Database error during verification.'});
    } catch (e) {
      print('Verification Error: $e');
      return _jsonResponse(500, {'error': 'An internal server error occurred'});
    }
  }

  /// HANDLER: Handles POST /api/profile/update
  Future<Response> updateProfileHandler(Request request) async {
    final payload = await _validateToken(request);
    if (payload == null) {
      return _jsonResponse(401, {'error': 'Unauthorized: Invalid or missing token'});
    }

    try {
      final userID = payload['id'] as int;
      final body = json.decode(await request.readAsString());
      final newName = body['name'] as String?;
      final newFplTeamID = body['fpl_team_ID'] as String?;

      if (newName == null && newFplTeamID == null) {
        return _jsonResponse(400, {'error': 'No fields provided for update.'});
      }

      final updates = <String, dynamic>{};
      final updateClauses = <String>[];

      // Use a single pool resource block for all DB operations in this handler
      final result = await _requestPool.withResource(() async {

        if (newFplTeamID != null) {
          // Check for existing FPL ID
          final existingFplId = await _dbConnection.query(
            "SELECT id FROM users WHERE fpl_team_id = @fplId AND id != @userId LIMIT 1",
            substitutionValues: {'fplId': newFplTeamID, 'userId': userID},
          );

          if (existingFplId.isNotEmpty) {
            throw Exception('FPL_TEAM_ID_EXISTS');
          }

          updateClauses.add('fpl_team_id = @fplId');
          updates['fplId'] = newFplTeamID;
        }

        if (newName != null) {
          updateClauses.add('name = @name');
          updates['name'] = newName;
        }

        updates['userId'] = userID;

        // Perform the update query
        return _dbConnection.query(
          "UPDATE users SET ${updateClauses.join(', ')} WHERE id = @userId RETURNING id, name, email, fpl_team_id, is_email_verified",
          substitutionValues: updates,
        );
      });


      if (result.isEmpty) {
        return _jsonResponse(404, {'error': 'User not found'});
      }

      final updatedUserRow = result.first.toColumnMap();
      final user = BackendUser.fromPostgreSQL(updatedUserRow);

      return _jsonResponse(200, user.toJson()..['message'] = 'Profile updated successfully');

    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Profile Update: $e');
      return _jsonResponse(500, {'error': 'Database error during profile update.'});
    } catch (e) {
      // Handle the custom exception thrown inside the pool block
      if (e.toString().contains('FPL_TEAM_ID_EXISTS')) {
        return _jsonResponse(409, {'error': 'FPL Team ID is already in use by another account.'});
      }
      print('Profile Update Error: $e');
      return _jsonResponse(500, {'error': 'Internal server error'});
    }
  }


  /// HANDLER: Handles POST /api/password/change
  Future<Response> changePasswordHandler(Request request) async {
    final payload = await _validateToken(request);
    if (payload == null) {
      return _jsonResponse(401, {'error': 'Unauthorized: Invalid or missing token'});
    }

    try {
      final userID = payload['id'] as int;
      final body = json.decode(await request.readAsString());
      final currentPassword = body['current_password'] as String?;
      final newPassword = body['new_password'] as String?;

      if (currentPassword == null || newPassword == null) {
        return _jsonResponse(400, {'error': 'Missing current or new password.'});
      }

      // 🔑 CRITICAL FIX: Wrap all database operations in the request pool
      final operationResult = await _requestPool.withResource(() async {

        // 1. Fetch the password hash
        final result = await _dbConnection.query(
          "SELECT password_hash FROM users WHERE id = @userId LIMIT 1",
          substitutionValues: {'userId': userID},
        );

        if (result.isEmpty) {
          throw Exception('User not found');
        }

        final storedHash = result.first.toColumnMap()['password_hash'] as String;

        if (!BCrypt.checkpw(currentPassword, storedHash)) {
          throw Exception('Incorrect current password');
        }

        final newHashedPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt());

        // 2. Execute the update
        await _dbConnection.execute(
          "UPDATE users SET password_hash = @newHash WHERE id = @userId",
          substitutionValues: {'newHash': newHashedPassword, 'userId': userID},
        );

        return true; // Return a success indicator

      });

      return _jsonResponse(200, {'message': 'Password updated successfully'});

    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Password Change: $e');
      return _jsonResponse(500, {'error': 'Database error during password change.'});
    } catch (e) {
      if (e.toString().contains('User not found')) {
        return _jsonResponse(404, {'error': 'User not found'});
      }
      if (e.toString().contains('Incorrect current password')) {
        return _jsonResponse(401, {'error': 'Incorrect current password'});
      }
      print('Password Change Error: $e');
      return _jsonResponse(500, {'error': 'Internal server error'});
    }
  }

  /// Handles POST /api/auth/google
  Future<Response> googleLoginHandler(Request request) async {
    try {
      // ... (Google token verification code remains unchanged) ...
      final body = json.decode(await request.readAsString());
      final idToken = body['id_token'] as String?;

      if (idToken == null) {
        return _jsonResponse(400, {'error': 'Missing Google ID token'});
      }

      final verificationUrl = Uri.parse(
          'https://oauth2.googleapis.com/tokeninfo?id_token=$idToken');

      final verificationResponse = await http.get(verificationUrl);

      if (verificationResponse.statusCode != 200) {
        return _jsonResponse(401, {'error': 'Invalid or expired Google ID token.'});
      }

      final googleUserPayload = json.decode(verificationResponse.body);
      final email = googleUserPayload['email'] as String?;
      final name = googleUserPayload['name'] as String?;

      final bool isVerifiedByGoogle = googleUserPayload['email_verified'] == 'true';
      if (email == null || !isVerifiedByGoogle) {
        return _jsonResponse(401, {'error': 'Google email not verified.'});
      }


      // 🔑 CRITICAL FIX: Wrap all database operations in the request pool
      final user = await _requestPool.withResource(() async {
        // Check for existing user
        final existingUserResult = await _dbConnection.query(
          "SELECT id, name, email, fpl_team_id, is_email_verified FROM users WHERE LOWER(email) = @email LIMIT 1",
          substitutionValues: {'email': email},
        );

        if (existingUserResult.isNotEmpty) {
          // User exists
          final userRow = existingUserResult.first.toColumnMap();
          return BackendUser.fromPostgreSQL(userRow);
        } else {
          // User does not exist: Register them automatically
          final dummyPasswordHash = BCrypt.hashpw('google_auth_placeholder', BCrypt.gensalt());

          // Insert new user, marking them as verified by default since Google confirmed it
          final insertResult = await _dbConnection.query(
            "INSERT INTO users (name, email, password_hash, is_email_verified) VALUES (@name, @email, @hash, TRUE) RETURNING id, name, email, fpl_team_id, is_email_verified",
            substitutionValues: {
              'name': name ?? 'Google User',
              'email': email,
              'hash': dummyPasswordHash,
            },
          );
          final newUserRow = insertResult.first.toColumnMap();
          return BackendUser.fromPostgreSQL(newUserRow);
        }
      });


      // Generate JWT, including the verification status
      final jwt = JWT({'id': user.id, 'email': user.email, 'verified': user.isEmailVerified});
      final token = jwt.sign(SecretKey(_jwtSecret), expiresIn: const Duration(days: 7));

      final userWithToken = user.toJson()..['token'] = token;

      return _jsonResponse(200, userWithToken);

    } on PostgreSQLException catch (e) {
      print('PostgreSQL Error during Google Login: $e');
      return _jsonResponse(500, {'error': 'Database error during Google login/registration.'});
    } catch (e) {
      print('Google Login Error: $e');
      return _jsonResponse(500, {'error': 'An internal server error occurred during Google Sign-In'});
    }
  }
}