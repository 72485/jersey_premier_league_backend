// bin/server.dart (FINAL - Concurrency Safe with package:pool)

import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';
import 'package:postgres/postgres.dart';
import 'package:dotenv/dotenv.dart' as env_helper;
import 'package:pool/pool.dart'; // 🔑 NEW: Concurrency Pool

import 'package:jersey_premier_league_backend/services/auth_service.dart';

// --- Environment Initialization ---
final env = env_helper.DotEnv(includePlatformEnvironment: true)..load();

// --- Database Initialization and Custom Pool ---
String _getRequiredEnv(String key) {
  final value = env[key];
  if (value == null || value.isEmpty) {
    throw Exception('Missing required environment variable: $key. Please check your .env file.');
  }
  return value;
}

// 🔑 NEW: A class to manage the single PostgreSQL connection and the Pool
class CustomDbPool {
  final Pool requestPool;
  final PostgreSQLConnection dbConnection;

  CustomDbPool({required this.requestPool, required this.dbConnection});
}

// 🔑 FIX: Function initializes the single connection AND the Request Pool
Future<CustomDbPool> _initializeDatabaseWithPool() async {
  try {
    final dbHost = _getRequiredEnv('DB_HOST');
    final dbPort = int.parse(_getRequiredEnv('DB_PORT'));
    final dbName = _getRequiredEnv('DB_NAME');
    final dbUser = _getRequiredEnv('DB_USER');
    final dbPassword = _getRequiredEnv('DB_PASSWORD');

    // 1. Initialize the single, persistent connection
    final conn = PostgreSQLConnection(
      dbHost,
      dbPort,
      dbName,
      username: dbUser,
      password: dbPassword,
      // Use useSSL: true for cloud providers like Neon/Render
      useSSL: true,
    );

    print('Attempting to connect to PostgreSQL...');
    await conn.open();
    print('Successfully connected to PostgreSQL!');

    // 2. Initialize schema (still necessary once)
    final schemaSql = await File('db/db_setup.sql').readAsString();
    print('Initializing database schema...');
    // Ensure schema setup uses the open connection
    await conn.transaction((ctx) async {
      await ctx.execute(schemaSql);
    });
    print('Database schema initialized successfully!');

    // 3. 🔑 CRITICAL: Initialize the generic Pool
    // This pool limits how many concurrent requests can use the single connection.
    final requestPool = Pool(5);

    return CustomDbPool(requestPool: requestPool, dbConnection: conn);

  } on FormatException {
    print('FATAL ERROR: DB_PORT environment variable is not a valid number.');
    exit(1);
  } on PostgreSQLException catch (e) {
    print('FATAL ERROR: Failed to initialize database: $e');
    exit(1);
  } catch (e) {
    print('FATAL ERROR: An unknown error occurred: $e');
    exit(1);
  }
}

// --- Server Setup and Router ---

void main() async {
  // 🔑 CRITICAL: Get the custom pool manager object
  final customDbPool = await _initializeDatabaseWithPool();
  final dbConnection = customDbPool.dbConnection;
  final requestPool = customDbPool.requestPool;

  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  final serverHost = _getRequiredEnv('SERVER_AUTHORITY');

  // Fetch all required SMTP environment variables and initialize EmailService
  final emailService = EmailService(
    smtpHost: _getRequiredEnv('SMTP_HOST'),
    smtpPort: int.parse(_getRequiredEnv('SMTP_PORT')),
    smtpUsername: _getRequiredEnv('SMTP_USERNAME'),
    smtpPassword: _getRequiredEnv('SMTP_PASSWORD'),
    smtpSsl: _getRequiredEnv('SMTP_SSL').toLowerCase() == 'true',
    senderEmail: _getRequiredEnv('SENDER_EMAIL'),
  );

  // 🔑 CRITICAL: Pass the single connection AND the Pool object
  final authService = BackendAuthService(dbConnection, requestPool, emailService, serverHost);

  final appRouter = Router();

  // Keep-Alive Route
  appRouter.get('/api/status', (Request request) => Response.ok('OK'));

  // Public Routes (No authentication required)
  appRouter.post('/api/register', authService.registerHandler);
  appRouter.post('/api/login', authService.loginHandler);
  appRouter.get('/api/verify', authService.verifyEmailHandler);

  // Protected Routes (Authentication required via JWT)
  appRouter.post('/api/profile/update', authService.updateProfileHandler);
  appRouter.post('/api/password/change', authService.changePasswordHandler);
  appRouter.post('/api/auth/google', authService.googleLoginHandler);
  appRouter.post('/api/profile/fpl-team-id', authService.updateFplTeamIdHandler);




  // CORS Middleware setup
  final handler = const Pipeline()
      .addMiddleware(_corsHeaders())
      .addMiddleware(logRequests())
      .addHandler(appRouter);

  // Start the server
  final server = await io.serve(handler, InternetAddress.anyIPv4, port);
  print('Server listening on http://${server.address.host}:${server.port}');
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