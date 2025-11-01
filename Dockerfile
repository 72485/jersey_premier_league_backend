# --- STAGE 1: BUILD ---
# Use the official Dart SDK image to compile the app
FROM dart:stable AS build

# Set the working directory
WORKDIR /app

# Copy pubspec files and resolve dependencies
COPY pubspec.* ./
RUN dart pub get

# Copy source code and AOT compile it
COPY . .
# Compile bin/server.dart to a native executable named 'server'
RUN dart compile exe bin/server.dart -o bin/server

# --- STAGE 2: RUNTIME ---
# Use the minimal 'scratch' base image for a tiny final image
FROM scratch

# Copy the Dart runtime libraries required for the executable from the build stage
# This is crucial for AOT executables to run on a minimal image
COPY --from=build /runtime/ /

# Copy the compiled server executable to the final image's expected location
COPY --from=build /app/bin/server /app/bin/server

# Expose the default port (8080 is a common default, but your app uses the PORT env var)
EXPOSE 8080

# Command to run the AOT-compiled server
# This fixes the "exec /app/bin/server: no such file or directory" error
CMD ["/app/bin/server"]