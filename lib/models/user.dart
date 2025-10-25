
/// Represents a User object as stored and processed on the backend server.
class BackendUser {
  final int id;
  final String name;
  final String email;
  // passwordHash is not included in the JSON response to the client.
  final String? fplTeamID;

  BackendUser({
    required this.id,
    required this.name,
    required this.email,
    this.fplTeamID,
  });

  /// Factory constructor to create a BackendUser object from a PostgreSQL row.
  /// This is used after a successful database query (e.g., during login).
  factory BackendUser.fromPostgreSQL(Map<String, dynamic> row) {
    return BackendUser(
      id: row['id'] as int,
      name: row['name'] as String,
      email: row['email'] as String,
      // FPL ID is nullable in the database
      fplTeamID: row['fpl_team_id'] as String?,
    );
  }

  /// Converts the BackendUser object to a Map that can be sent as a JSON response.
  /// NOTE: This map does NOT include the sensitive password hash.
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'email': email,
      // The frontend expects "fpl_team_ID" in camelCase/snake_case consistency
      'fpl_team_ID': fplTeamID,
      // The token is added in the AuthService after creation/login.
    };
  }
}
