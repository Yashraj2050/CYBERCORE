"""
CYBERCORE Backend — AI Assistant Router

Provides chat endpoints for conversational threat triage, scam advice,
and digital safety guidance.
"""

import logging
from typing import Optional, List, Dict
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.limiter import limiter
from app.services.ai_service import generate_ai_response, SUGGESTED_QUESTIONS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ai", tags=["AI Assistant"])


class ChatMessage(BaseModel):
    role: str = Field(..., description="Role: 'user' or 'assistant'")
    content: str = Field(..., description="Message text")


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=2, max_length=2000, description="User prompt or security question")
    history: Optional[List[ChatMessage]] = Field(default=[], description="Recent conversation turns")


class ChatResponse(BaseModel):
    response: str
    suggested_followups: List[str]


@router.post("/chat", response_model=ChatResponse)
@limiter.limit("15/minute")
async def chat_with_cybercore_ai(payload: ChatRequest, request: Request):
    """
    Interact with the CYBERCORE AI Cybersecurity Advisor.
    Provides instant analysis, explanations, and risk mitigation strategies.
    """
    user_msg = payload.message.strip()
    if not user_msg:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Chat message cannot be empty.",
        )

    history_dicts = [{"role": m.role, "content": m.content} for m in payload.history]
    answer = await generate_ai_response(user_msg, chat_history=history_dicts)

    return ChatResponse(
        response=answer,
        suggested_followups=[
            "How do I spot phishing signs in an email?",
            "What should I do if my password was found in a breach?",
            "How does the CYBERCORE Chrome Extension protect me in real-time?",
        ],
    )


@router.get("/suggestions")
async def get_suggested_prompts():
    """Retrieve sample questions for the AI assistant."""
    return {"suggestions": SUGGESTED_QUESTIONS}
