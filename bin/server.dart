import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';
import 'package:postgres/postgres.dart';
import 'package:dotenv/dotenv.dart' as env_helper;

// Fix path to use the package alias
import 'package:jersey_premier_league_backend/services/auth_service.dart';

// --- Configuration Fix ---
// Explicitly define the IP address of the hotspot interface.
// This forces the server to bind to this specific network interface.
const String HOTSPOT_IP = '192.168.137.52';
// ---

// --- Environment Initialization ---
// Initialize the DotEnv object and load variables from .env file immediately.
final env = env_helper.DotEnv(includePlatformEnvironment: true)..load();

// --- Database Initialization and Connection ---

// Helper to get an environment variable or throw a descriptive error
String _getRequiredEnv(String key) {
  // Access the top-level 'env' map which is already loaded
  final value = env[key];
  if (value == null || value.isEmpty) {
    throw Exception('Missing required environment variable: $key. Please check your .env file.');
  }
  return value;
}

Future<PostgreSQLConnection> _initializeDatabase() async {
  // NO NEED TO CALL env.load() HERE, it's done at the top-level

  // Use the helper function for robust error handling
  try {
    final dbHost = _getRequiredEnv('DB_HOST');
    final dbPortString = _getRequiredEnv('DB_PORT');
    final dbName = _getRequiredEnv('DB_NAME');
    final dbUser = _getRequiredEnv('DB_USER');
    final dbPassword = _getRequiredEnv('DB_PASSWORD');

    // Parse the port separately
    final dbPort = int.parse(dbPortString);

    final conn = PostgreSQLConnection(
      dbHost,
      dbPort,
      dbName,
      username: dbUser,
      password: dbPassword,
      // sslMode: SslMode.prefer,
    );

    print('Attempting to connect to PostgreSQL...');
    await conn.open();
    print('Successfully connected to PostgreSQL!');

    // Read and execute the schema initialization script
    // NOTE: Ensure 'db/db_setup.sql' contains pure SQL without psql meta-commands (\).
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
    print('Please check your PostgreSQL server status, database name, and credentials in the .env file.');
    exit(1);
  } catch (e) {
    print('FATAL ERROR: An unknown error occurred during database setup. Details: $e');
    exit(1);
  }
}

// --- Server Setup and Router ---

void main() async {
  final dbConnection = await _initializeDatabase();
  final authService = BackendAuthService(dbConnection);

  final appRouter = Router();

  // Public Routes (No authentication required)
  appRouter.post('/api/register', authService.registerHandler);
  appRouter.post('/api/login', authService.loginHandler);

  // Protected Routes (Authentication required via JWT)
  appRouter.post('/api/profile/update', authService.updateProfileHandler);
  appRouter.post('/api/password/change', authService.changePasswordHandler);

  appRouter.post('/api/auth/google', authService.googleLoginHandler);

// ...

  // CORS Middleware setup
  final handler = const Pipeline()
      .addMiddleware(_corsHeaders())
      .addMiddleware(logRequests())
      .addHandler(appRouter);

  // Start the server
  final port = int.parse(Platform.environment['PORT'] ?? '8080');

  // --- CRITICAL BINDING FIX ---
  // We use the explicit HOTSPOT_IP instead of InternetAddress.anyIPv4 to ensure
  // the server correctly binds to the interface created by the mobile hotspot.
  final server = await io.serve(handler, InternetAddress.anyIPv4, port);
  // ---------------------------

  print('Server listening on http://${server.address.host}:${server.port}');
  print('Ready to handle requests from your Flutter app.');
}

// Middleware to handle CORS (Cross-Origin Resource Sharing)
Middleware _corsHeaders() {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*', // Allows all origins
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Origin, Content-Type, Authorization',
  };

  return (Handler inner) {
    return (Request request) async {
      if (request.method == 'OPTIONS') {
        // Handle CORS preflight requests
        return Response.ok(null, headers: corsHeaders);
      }
      final response = await inner(request);
      return response.change(headers: corsHeaders);
    };
  };
}