# Architecture

This document outlines the initial architecture for AI-SOC.

## Runtime flow

Frontend -> Backend -> MongoDB

Frontend -> Backend -> ML Service

## Components

- Frontend: React + TypeScript + Vite
- Backend: Node.js + Express + TypeScript
- Database: MongoDB via Docker
- ML service: Python + FastAPI

## Current scope

The initial project establishes a working baseline with health checks and status pages. Advanced security features are intentionally deferred.
