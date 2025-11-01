/// Represents a User object as stored and processed on the backend server.
class BackendUser {
  final int id;
  final String name;
  final String email;
  final String? fplTeamID;
  final bool isEmailVerified; // 🆕 NEW
  final String? verificationToken; // 🆕 NEW (optional)

  BackendUser({
    required this.id,
    required this.name,
    required this.email,
    required this.isEmailVerified, // 🆕 NEW
    this.fplTeamID,
    this.verificationToken, // 🆕 NEW
  });

  /// Factory constructor to create a BackendUser object from a PostgreSQL row.
  factory BackendUser.fromPostgreSQL(Map<String, dynamic> row) {
    return BackendUser(
      id: row['id'] as int,
      name: row['name'] as String,
      email: row['email'] as String,
      fplTeamID: row['fpl_team_id'] as String?,
      isEmailVerified: row['is_email_verified'] as bool, // 🆕 NEW
      verificationToken: row['verification_token'] as String?, // 🆕 NEW
    );
  }

  /// Converts the BackendUser object to a Map that can be sent as a JSON response.
  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'email': email,
      'fpl_team_ID': fplTeamID,
      'is_email_verified': isEmailVerified, // 🆕 NEW
      // verificationToken is generally NOT sent to the client
    };
  }
}