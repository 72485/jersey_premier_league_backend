import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';
import 'package:postgres/postgres.dart';
import 'package:dotenv/dotenv.dart' as env_helper;

// Fix path to use the package alias
import 'package:jersey_premier_league_backend/services/auth_service.dart';

// --- Configuration Fix ---
const String HOTSPOT_IP = '192.168.137.52';
// ---

// --- Environment Initialization ---
final env = env_helper.DotEnv(includePlatformEnvironment: true)..load();

// --- Database Initialization and Connection ---
String _getRequiredEnv(String key) {
  final value = env[key];
  if (value == null || value.isEmpty) {
    throw Exception('Missing required environment variable: $key. Please check your .env file.');
  }
  return value;
}

Future<PostgreSQLConnection> _initializeDatabase() async {
  try {
    final dbHost = _getRequiredEnv('DB_HOST');
    final dbPortString = _getRequiredEnv('DB_PORT');
    final dbName = _getRequiredEnv('DB_NAME');
    final dbUser = _getRequiredEnv('DB_USER');
    final dbPassword = _getRequiredEnv('DB_PASSWORD');

    final dbPort = int.parse(dbPortString);

    final conn = PostgreSQLConnection(
      dbHost,
      dbPort,
      dbName,
      username: dbUser,
      password: dbPassword,
      // 🔑 CRITICAL FIX: Ensure SSL is enabled for cloud databases
      useSSL: true,
    );

    print('Attempting to connect to PostgreSQL...');
    await conn.open();
    print('Successfully connected to PostgreSQL!');

    final schemaSql = await File('db/db_setup.sql').readAsString();
    print('Initializing database schema...');

    await conn.transaction((ctx) async {
      await ctx.execute(schemaSql);
    });
    print('Database schema initialized successfully!');

    return conn;

  } on FormatException {
    print('FATAL ERROR: DB_PORT environment variable is not a valid number. Please check your .env file.');
    exit(1);
  } on PostgreSQLException catch (e) {
    print('FATAL ERROR: Failed to initialize database: $e');
    print('If the error is "connection is insecure" or "no SSL", you must update the postgres package.');
    exit(1);
  } catch (e) {
    print('FATAL ERROR: An unknown error occurred during database setup. Details: $e');
    exit(1);
  }
}

// --- Server Setup and Router ---

void main() async {
  final dbConnection = await _initializeDatabase();

  // Get port (used for local binding)
  final port = int.parse(Platform.environment['PORT'] ?? '8080');

  // Fetch the publicly accessible authority (SERVER_AUTHORITY)
  final serverHost = _getRequiredEnv('SERVER_AUTHORITY');

  // 🔑 START OF CRITICAL FIX BLOCK (Removed SMTP, using API Key)
  // Fetch the SendGrid API Key (stored in the old SMTP_PASSWORD variable)
  final sendGridApiKey = _getRequiredEnv('SMTP_PASSWORD');
  final senderEmail = _getRequiredEnv('SENDER_EMAIL');

  print('LOG: SendGrid Configuration - Host: api.sendgrid.com, User: apikey, Key Loaded.');

  // Initialize the EmailService with the new, required API arguments
  final emailService = EmailService(
    sendGridApiKey: sendGridApiKey, // The SendGrid API Key
    senderEmail: senderEmail,
    serverHost: serverHost,         // The host used to generate the verification link
  );
  // 🔑 END OF CRITICAL FIX BLOCK

  // Pass the initialized services to the AuthService
  final authService = BackendAuthService(dbConnection, emailService, serverHost);

  final appRouter = Router();

  // Public Routes (No authentication required)
  appRouter.post('/api/register', authService.registerHandler);
  appRouter.post('/api/login', authService.loginHandler);
  appRouter.get('/api/verify', authService.verifyEmailHandler);

  // Protected Routes (Authentication required via JWT)
  appRouter.post('/api/profile/update', authService.updateProfileHandler);
  appRouter.post('/api/password/change', authService.changePasswordHandler);
  appRouter.post('/api/auth/google', authService.googleLoginHandler);

  // CORS Middleware setup
  final handler = const Pipeline()
      .addMiddleware(_corsHeaders())
      .addMiddleware(logRequests())
      .addHandler(appRouter);

  // Start the server
  // Note: Serving on InternetAddress.anyIPv4 allows all network access (local and public).
  final server = await io.serve(handler, InternetAddress.anyIPv4, port);

  print('Server listening on http://${server.address.host}:${server.port}');
  print('Verification links will use: http://$serverHost/api/verify');
}

// Middleware to handle CORS (Cross-Origin Resource Sharing)
Middleware _corsHeaders() {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Origin, Content-Type, Authorization',
  };

  return (Handler inner) {
    return (Request request) async {
      if (request.method == 'OPTIONS') {
        return Response.ok(null, headers: corsHeaders);
      }
      final response = await inner(request);
      return response.change(headers: corsHeaders);
    };
  };
}