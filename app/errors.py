"""
Global error handlers for the Agentic Honeypot API.
Ensures all errors return consistent JSON responses.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException, RequestValidationError


def create_error_response(status_code: int, message: str) -> JSONResponse:
    """Create a standardized JSON error response."""
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "error",
            "message": message
        }
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "Request error"
    return create_error_response(exc.status_code, message)


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle request validation errors (invalid/missing request body)."""
    return create_error_response(400, "Invalid or missing request fields")


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle all unhandled exceptions with a 500 fallback."""
    return create_error_response(500, "Internal server error")
