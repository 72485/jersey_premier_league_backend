# Use an official Dart image as the base for building
FROM dart:stable AS build

# Set working directory
WORKDIR /app

# Copy pubspec and fetch dependencies
COPY pubspec.* .
RUN dart pub get

# Copy the rest of the application source code
COPY . .

# Build the server executable
RUN dart compile exe bin/server.dart -o bin/server

# --- Final Stage: Minimal Runtime Image ---
# Use a lightweight Alpine base image for the running environment
FROM alpine:latest
RUN apk add --no-cache openssl ca-certificates bash

# Set working directory
WORKDIR /app

# Copy the pre-compiled server executable from the build stage
COPY --from=build /app/bin/server bin/

# Copy assets like the database setup script (if needed for runtime initialization)
COPY db/db_setup.sql db/

# Expose the port your application is configured to use
EXPOSE 8080

# Command to run your compiled server executable
CMD ["/app/bin/server"]