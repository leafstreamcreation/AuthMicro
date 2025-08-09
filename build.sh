#!/bin/bash

# Build script for Authentication Microservice

echo "Building Authentication Microservice..."

# Clean and build the project
echo "Cleaning and building Maven project..."
mvn clean package -DskipTests

if [ $? -eq 0 ]; then
    echo "Maven build successful!"
    
    # Build Docker image
    echo "Building Docker image..."
    docker build -t auth-api:latest .
    
    if [ $? -eq 0 ]; then
        echo "Docker image built successfully!"
        echo "You can now run: docker-compose up"
    else
        echo "Docker build failed!"
        exit 1
    fi
else
    echo "Maven build failed!"
    exit 1
fi

echo "Build completed successfully!"
