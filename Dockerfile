# --- STAGE 1: BUILD ---
# Use the official Dart SDK image to compile the app
FROM dart:stable AS build

# Set the working directory for the build
WORKDIR /app

# Copy pubspec files and resolve dependencies
COPY pubspec.* ./
RUN dart pub get

# Copy all application source code, including the db/ directory, for compilation and file access
# We also copy the source code of your packages, as this is needed for 'dart compile exe'
COPY . .

# Compile bin/server.dart to a native executable named 'server'
RUN dart compile exe bin/server.dart -o bin/server

# ----------------------

# --- STAGE 2: RUNTIME ---
# Use the minimal 'scratch' base image for a tiny final image
FROM scratch

# Set the working directory in the final image
# This ensures relative file paths like 'db/db_setup.sql' correctly resolve from the root of the app
WORKDIR /app

# Copy the Dart runtime libraries required for the executable
COPY --from=build /runtime/ /

# Copy the compiled server executable
COPY --from=build /app/bin/server /app/bin/server

# 🔑 FIX: Copy the 'db' directory with the setup script
# This is the crucial step to resolve 'db/db_setup.sql' not found
COPY --from=build /app/db /app/db

# Expose the default port (Render will use the $PORT env var, but this is good practice)
EXPOSE 8080

# Command to run the AOT-compiled server
CMD ["/app/bin/server"]